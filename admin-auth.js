const COOKIE = '__Host-lfp_admin';
const SESSION_SECONDS = 8 * 60 * 60;
const response = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
});
const cookie = (token, age = SESSION_SECONDS) => `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${age}`;
const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
const bytes = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const encoder = new TextEncoder();
export function generateSignInCode() {
  const random = new Uint32Array(1);
  do { crypto.getRandomValues(random); } while (random[0] >= 4294800000);
  return String(100000 + random[0] % 900000);
}
export const clearAdminCookie = () => cookie('', 0);
export async function adminSessionCookie(user, secret) {
  if (user.role !== 'admin') return clearAdminCookie();
  return cookie(await sign(user, secret));
}
async function key(secret) {
  return crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function sign(user, secret) {
  const header = encode(encoder.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const payload = encode(encoder.encode(JSON.stringify({ uid: user.id, aud: 'admin', exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS })));
  const data = `${header}.${payload}`;
  return `${data}.${encode(await crypto.subtle.sign('HMAC', await key(secret), encoder.encode(data)))}`;
}
export async function getAdmin(request, env) {
  const match = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)__Host-lfp_admin=([^;]+)/);
  if (!match) return null;
  let payload;
  try {
    const parts = match[1].split('.');
    if (parts.length !== 3) return null;
    if (!await crypto.subtle.verify('HMAC', await key(env.JWT_SECRET), bytes(parts[2]), encoder.encode(`${parts[0]}.${parts[1]}`))) return null;
    payload = JSON.parse(new TextDecoder().decode(bytes(parts[1])));
    if (payload.aud !== 'admin' || !Number.isFinite(payload.exp) || payload.exp <= Date.now() / 1000) return null;
  } catch { return null; }
  // Recheck the live role so removing admin access takes effect immediately.
  return env.DB.prepare("SELECT id, email, display_name, role FROM users WHERE id = ? AND role = 'admin'").bind(payload.uid).first();
}
export async function handleAdminAuth(request, env, path) {
  if (path === '/api/admin/auth/me' && request.method === 'GET') {
    const user = await getAdmin(request, env);
    return user ? response({ uid: user.id, email: user.email, displayName: user.display_name, role: user.role }) : response({ error: 'Admin sign-in required' }, 401);
  }
  if (request.method !== 'POST') return response({ error: 'Not found' }, 404);
  if (request.headers.get('Origin') !== new URL(request.url).origin) return response({ error: 'Invalid request origin' }, 403);
  if (path === '/api/admin/auth/logout') return response({ ok: true }, 200, { 'Set-Cookie': cookie('', 0) });
  if (!['/api/admin/auth/request-code', '/api/admin/auth/verify-code'].includes(path)) return response({ error: 'Not found' }, 404);
  let input;
  try { input = await request.json(); } catch { return response({ error: 'Invalid request' }, 400); }
  const email = typeof input?.email === 'string' ? input.email.trim().toLowerCase() : '';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return response({ error: 'Enter a valid email address.' }, 400);
  const requesting = path.endsWith('/request-code');
  const event = requesting ? 'admin_code_requested' : 'admin_code_attempt';
  const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM login_events WHERE email = ? AND event = ? AND created_at > datetime('now', '-15 minutes')").bind(email, event).first();
  if (count.count >= (requesting ? 3 : 5)) return response({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);
  await env.DB.prepare('INSERT INTO login_events (id, email, event) VALUES (?, ?, ?)').bind(crypto.randomUUID(), email, event).run();
  const user = await env.DB.prepare("SELECT id, email, display_name, role FROM users WHERE email = ? AND role = 'admin'").bind(email).first();
  // Keep the two sign-in challenges separate; each verifies the live account role.
  const otpEmail = `admin:${email}`;
  if (requesting) {
    if (!user) return response({ ok: true });
    const code = generateSignInCode();
    const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    await env.DB.batch([
      env.DB.prepare('DELETE FROM otp_codes WHERE email = ?').bind(otpEmail),
      env.DB.prepare('INSERT INTO otp_codes (id, email, code, expires_at) VALUES (?, ?, ?, ?)').bind(crypto.randomUUID(), otpEmail, code, expires),
    ]);
    try {
      const sent = await fetch('https://api.resend.com/emails', {
        method: 'POST', headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: 'Lion Forge Peptides <support@lionforgepeptides.com>', to: [email], subject: 'Lion Forge Admin Sign-In Code',
          html: `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto"><h2>Lion Forge Admin</h2><p>Your admin sign-in code is:</p><p style="font-size:36px;font-weight:bold;letter-spacing:6px">${code}</p><p>Expires in 15 minutes. If you did not request this code, ignore this email.</p></div>` }),
      });
      if (!sent.ok) throw new Error('Delivery failed');
    } catch {
      await env.DB.prepare('DELETE FROM otp_codes WHERE email = ? AND code = ?').bind(otpEmail, code).run();
      return response({ error: 'Unable to send a code right now. Please try again later.' }, 502);
    }
    return response({ ok: true });
  }
  if (!user || !/^\d{6}$/.test(String(input.code || ''))) return response({ error: 'Invalid or expired admin code.' }, 401);
  // Atomic consumption prevents concurrent requests from reusing a valid code.
  const used = await env.DB.prepare("UPDATE otp_codes SET used = 1 WHERE email = ? AND code = ? AND used = 0 AND datetime(expires_at) > datetime('now') RETURNING id").bind(otpEmail, String(input.code)).first();
  if (!used) return response({ error: 'Invalid or expired admin code.' }, 401);
  await env.DB.prepare('INSERT INTO login_events (id, email, event) VALUES (?, ?, ?)').bind(crypto.randomUUID(), email, 'admin_login_success').run();
  return response({ ok: true }, 200, { 'Set-Cookie': await adminSessionCookie(user, env.JWT_SECRET) });
}
