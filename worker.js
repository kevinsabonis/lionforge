/**
 * Lion Forge Peptides — Cloudflare Worker
 * Handles /api/* routes; all other requests fall through to static assets.
 */

// ── JWT helpers ────────────────────────────────────────────────────────────

const enc = new TextEncoder();

async function jwtSign(payload, secret) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${header}.${body}`));
  return `${header}.${body}.${b64url(sig)}`;
}

async function jwtVerify(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  const valid = await crypto.subtle.verify(
    'HMAC', key, b64decode(parts[2]), enc.encode(`${parts[0]}.${parts[1]}`)
  );
  if (!valid) return null;
  const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

function b64url(data) {
  const str = typeof data === 'string' ? data : String.fromCharCode(...new Uint8Array(data));
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64decode(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

// ── Password hashing (PBKDF2 via SubtleCrypto) ─────────────────────────────

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await pbkdf2(password, salt);
  const combined = new Uint8Array(salt.length + key.byteLength);
  combined.set(salt);
  combined.set(new Uint8Array(key), salt.length);
  return btoa(String.fromCharCode(...combined));
}

async function verifyPassword(password, stored) {
  const combined = Uint8Array.from(atob(stored), c => c.charCodeAt(0));
  const salt = combined.slice(0, 16);
  const key = await pbkdf2(password, salt);
  const storedKey = combined.slice(16);
  const keyBytes = new Uint8Array(key);
  if (keyBytes.length !== storedKey.length) return false;
  // Constant-time comparison
  let diff = 0;
  for (let i = 0; i < keyBytes.length; i++) diff |= keyBytes[i] ^ storedKey[i];
  return diff === 0;
}

async function pbkdf2(password, salt) {
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    baseKey, 256
  );
}

// ── Responses ──────────────────────────────────────────────────────────────

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });

const err = (msg, status = 400) => json({ error: msg }, status);

// ── Auth middleware ────────────────────────────────────────────────────────

async function getUser(request, secret) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  if (!match) return null;
  return jwtVerify(match[1], secret);
}

function sessionCookie(token) {
  return `session=${token}; HttpOnly; Secure; SameSite=Strict; Max-Age=604800; Path=/`;
}

function clearCookie() {
  return `session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/`;
}

// ── Router ─────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Only handle /api/* routes; everything else serves static assets
    if (!path.startsWith('/api/')) {
      return env.ASSETS.fetch(request);
    }

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': url.origin,
          'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Credentials': 'true',
        },
      });
    }

    try {
      // ── Auth routes ──────────────────────────────────────────────────────
      if (path === '/api/auth/register' && method === 'POST')
        return handleRegister(request, env);
      if (path === '/api/auth/login' && method === 'POST')
        return handleLogin(request, env);
      if (path === '/api/auth/logout' && method === 'POST')
        return handleLogout();
      if (path === '/api/auth/me' && method === 'GET')
        return handleMe(request, env);
      if (path === '/api/auth/reset-request' && method === 'POST')
        return handleResetRequest(request, env);
      if (path === '/api/auth/reset-password' && method === 'POST')
        return handleResetPassword(request, env);

      // ── Public routes ────────────────────────────────────────────────────
      if (path === '/api/products' && method === 'GET')
        return handleGetProducts(env);
      if (path === '/api/announcements' && method === 'GET')
        return handleGetAnnouncements(env);

      // ── Order routes ─────────────────────────────────────────────────────
      if (path === '/api/orders/place' && method === 'POST')
        return handlePlaceOrder(request, env);
      if (path === '/api/orders' && method === 'GET')
        return handleGetOrders(request, env);

      // ── Admin routes ─────────────────────────────────────────────────────
      if (path.startsWith('/api/admin/')) return handleAdmin(request, env, path, method);

      return err('Not found', 404);
    } catch (e) {
      console.error(e);
      return err('Internal server error', 500);
    }
  },
};

// ── Auth handlers ──────────────────────────────────────────────────────────

async function handleRegister(request, env) {
  const { email, password, displayName } = await request.json();
  if (!email || !password || !displayName) return err('All fields required');
  if (password.length < 6) return err('Password must be at least 6 characters');

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  if (existing) return err('Email already in use');

  const hash = await hashPassword(password);
  const id = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO users (id, email, password_hash, display_name) VALUES (?, ?, ?, ?)'
  ).bind(id, email.toLowerCase(), hash, displayName).run();

  const token = await jwtSign(
    { uid: id, email: email.toLowerCase(), displayName, role: 'customer', exp: Math.floor(Date.now() / 1000) + 604800 },
    env.JWT_SECRET
  );
  return json({ uid: id, email: email.toLowerCase(), displayName, role: 'customer' }, 200, {
    'Set-Cookie': sessionCookie(token),
  });
}

async function handleLogin(request, env) {
  const { email, password } = await request.json();
  if (!email || !password) return err('Email and password required');

  const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  if (!user) return err('Invalid email or password', 401);

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return err('Invalid email or password', 401);

  const token = await jwtSign(
    { uid: user.id, email: user.email, displayName: user.display_name, role: user.role, exp: Math.floor(Date.now() / 1000) + 604800 },
    env.JWT_SECRET
  );
  return json({ uid: user.id, email: user.email, displayName: user.display_name, role: user.role }, 200, {
    'Set-Cookie': sessionCookie(token),
  });
}

function handleLogout() {
  return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() });
}

async function handleMe(request, env) {
  const user = await getUser(request, env.JWT_SECRET);
  if (!user) return err('Unauthenticated', 401);
  return json({ uid: user.uid, email: user.email, displayName: user.displayName, role: user.role });
}

async function handleResetRequest(request, env) {
  const { email } = await request.json();
  if (!email) return err('Email required');

  const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  // Always return ok to prevent email enumeration
  if (!user) return json({ ok: true });

  const token = crypto.randomUUID().replace(/-/g, '');
  const expires = new Date(Date.now() + 3600000).toISOString(); // 1 hour
  await env.DB.prepare(
    'INSERT INTO reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)'
  ).bind(token, user.id, expires).run();

  // Return token so the client can send it via EmailJS
  return json({ ok: true, resetToken: token });
}

async function handleResetPassword(request, env) {
  const { token, newPassword } = await request.json();
  if (!token || !newPassword) return err('Token and new password required');
  if (newPassword.length < 6) return err('Password must be at least 6 characters');

  const row = await env.DB.prepare(
    'SELECT * FROM reset_tokens WHERE token = ? AND used = 0 AND expires_at > datetime(\'now\')'
  ).bind(token).first();
  if (!row) return err('Invalid or expired reset token', 400);

  const hash = await hashPassword(newPassword);
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(hash, row.user_id),
    env.DB.prepare('UPDATE reset_tokens SET used = 1 WHERE token = ?').bind(token),
  ]);
  return json({ ok: true });
}

// ── Product handlers ───────────────────────────────────────────────────────

async function handleGetProducts(env) {
  const row = await env.DB.prepare('SELECT value FROM config WHERE key = ?').bind('products').first();
  const data = row ? JSON.parse(row.value) : { list: [] };
  return json(data);
}

// ── Announcement handlers ──────────────────────────────────────────────────

async function handleGetAnnouncements(env) {
  const { results } = await env.DB.prepare(
    'SELECT * FROM announcements WHERE published = 1 ORDER BY created_at DESC'
  ).all();
  return json(results);
}

// ── Order handlers ─────────────────────────────────────────────────────────

const SHIPPING_RATES = { ground: 10, expedited: 15 };
const DISCOUNTS = { LION10: 0.10, FORGE20: 0.20, RESEARCH15: 0.15 };
const UNLIMITED_THRESHOLD = 100;
const round2 = n => Math.round(n * 100) / 100;

async function handlePlaceOrder(request, env) {
  const user = await getUser(request, env.JWT_SECRET);
  const uid = user ? user.uid : 'guest';
  const authEmail = user ? user.email : null;

  const data = await request.json();
  const rawItems = Array.isArray(data.items) ? data.items : null;
  if (!rawItems || rawItems.length === 0) return err('Your cart is empty');

  const requested = rawItems.map(it => ({
    id: Number(it.id),
    variantIndex: Number(it.variantIndex),
    qty: Math.floor(Number(it.qty)),
  }));
  for (const r of requested) {
    if (!Number.isFinite(r.id) || !Number.isInteger(r.variantIndex) || r.variantIndex < 0 ||
        !Number.isInteger(r.qty) || r.qty < 1 || r.qty > 999)
      return err('A cart item was malformed. Please return to the shop and re-add your items.');
  }

  const customer = data.customer || {};
  const displayName = String(customer.name || '').trim().slice(0, 200);
  const email = String(customer.email || authEmail || '').trim().slice(0, 200);
  const address = String(customer.address || '').trim().slice(0, 1000);
  if (!displayName || !address) return err('A name and shipping address are required.');

  const shippingMethod = String(data.shippingMethod || 'ground').toLowerCase() === 'expedited' ? 'expedited' : 'ground';
  const discountCode = String(data.discountCode || '').trim().toUpperCase();
  const paymentMethod = String(data.paymentMethod || '').slice(0, 40);

  // D1 doesn't support multi-statement transactions like Firestore, but we
  // can use batch() for atomicity across writes. We read first then batch write.
  const prodRow = await env.DB.prepare('SELECT value FROM config WHERE key = ?').bind('products').first();
  if (!prodRow) return err('Product catalog unavailable', 503);
  const { list } = JSON.parse(prodRow.value);
  const byId = new Map(list.map(p => [Number(p.id), p]));

  let subtotal = 0;
  const lineItems = [];
  for (const r of requested) {
    const product = byId.get(r.id);
    if (!product) return err('An item in your cart is no longer available.');
    if (product.hidden === true) return err(`${product.name} is not currently available.`);
    const variant = product.variants && product.variants[r.variantIndex];
    if (!variant) return err(`A selected option for ${product.name} is no longer available.`);
    const stock = Number(variant.stock);
    const unlimited = Number.isFinite(stock) && stock >= UNLIMITED_THRESHOLD;
    if (!unlimited && (!Number.isFinite(stock) || stock < r.qty))
      return err(`${product.name} (${variant.label}) only has ${Number.isFinite(stock) ? stock : 0} in stock.`);
    const lineTotal = round2(Number(variant.price) * r.qty);
    subtotal += lineTotal;
    lineItems.push({ id: r.id, variantIndex: r.variantIndex, name: product.name, variant: variant.label, qty: r.qty, price: Number(variant.price), lineTotal });
  }
  subtotal = round2(subtotal);

  const shipping = SHIPPING_RATES[shippingMethod];
  const discountRate = DISCOUNTS[discountCode] || 0;
  const discount = round2(subtotal * discountRate);
  const total = Math.max(0, round2(subtotal + shipping - discount));

  // Decrement finite stock
  const newList = list.map(p => {
    const hits = requested.filter(r => r.id === Number(p.id));
    if (!hits.length) return p;
    return {
      ...p, variants: p.variants.map((v, idx) => {
        const hit = hits.find(r => r.variantIndex === idx);
        if (!hit) return v;
        const s = Number(v.stock);
        if (Number.isFinite(s) && s >= UNLIMITED_THRESHOLD) return v;
        return { ...v, stock: s - hit.qty };
      })
    };
  });

  const settingsRow = await env.DB.prepare('SELECT value FROM config WHERE key = ?').bind('lastOrderNum').first();
  const lastOrderNum = settingsRow ? Number(settingsRow.value) : 53;
  const orderNum = lastOrderNum + 1;
  const orderId = crypto.randomUUID();
  const orderDate = new Date().toISOString();

  await env.DB.batch([
    env.DB.prepare('UPDATE config SET value = ? WHERE key = ?').bind(String(orderNum), 'lastOrderNum'),
    env.DB.prepare('UPDATE config SET value = ? WHERE key = ?').bind(JSON.stringify({ list: newList }), 'products'),
    env.DB.prepare(`INSERT INTO orders (id, order_num, status, uid, display_name, email, address, payment_method, shipping_method, items, subtotal, shipping, discount, discount_code, total, date) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(orderId, orderNum, 'pending', uid, displayName, email, address, paymentMethod,
        shippingMethod === 'expedited' ? 'Expedited' : 'Ground',
        JSON.stringify(lineItems), subtotal, shipping, discount,
        discountRate ? discountCode : '', total, orderDate),
  ]);

  return json({ orderId, orderNum, items: lineItems, subtotal, shipping, discount, total });
}

async function handleGetOrders(request, env) {
  const user = await getUser(request, env.JWT_SECRET);
  if (!user) return err('Unauthenticated', 401);
  const { results } = await env.DB.prepare(
    'SELECT * FROM orders WHERE uid = ? ORDER BY created_at DESC'
  ).bind(user.uid).all();
  return json(results.map(o => ({ ...o, items: JSON.parse(o.items) })));
}

// ── Admin handlers ─────────────────────────────────────────────────────────

async function handleAdmin(request, env, path, method) {
  const user = await getUser(request, env.JWT_SECRET);
  if (!user || user.role !== 'admin') return err('Forbidden', 403);

  // Orders
  if (path === '/api/admin/orders' && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT * FROM orders ORDER BY created_at DESC').all();
    return json(results.map(o => ({ ...o, items: JSON.parse(o.items) })));
  }
  const orderMatch = path.match(/^\/api\/admin\/orders\/([^/]+)$/);
  if (orderMatch && method === 'PUT') {
    const body = await request.json();
    await env.DB.prepare('UPDATE orders SET status = ? WHERE id = ?').bind(body.status, orderMatch[1]).run();
    return json({ ok: true });
  }

  // Products
  if (path === '/api/admin/products' && method === 'GET') {
    const row = await env.DB.prepare('SELECT value FROM config WHERE key = ?').bind('products').first();
    return json(row ? JSON.parse(row.value) : { list: [] });
  }
  if (path === '/api/admin/products' && method === 'PUT') {
    const body = await request.json();
    await env.DB.prepare('UPDATE config SET value = ? WHERE key = ?').bind(JSON.stringify(body), 'products').run();
    return json({ ok: true });
  }

  // Announcements
  if (path === '/api/admin/announcements' && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT * FROM announcements ORDER BY created_at DESC').all();
    return json(results);
  }
  if (path === '/api/admin/announcements' && method === 'POST') {
    const { title, content, published } = await request.json();
    const id = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO announcements (id, title, content, published) VALUES (?, ?, ?, ?)'
    ).bind(id, title || '', content || '', published ? 1 : 0).run();
    return json({ ok: true, id });
  }
  const annMatch = path.match(/^\/api\/admin\/announcements\/([^/]+)$/);
  if (annMatch && method === 'PUT') {
    const { title, content, published } = await request.json();
    await env.DB.prepare(
      'UPDATE announcements SET title = ?, content = ?, published = ?, updated_at = datetime(\'now\') WHERE id = ?'
    ).bind(title, content, published ? 1 : 0, annMatch[1]).run();
    return json({ ok: true });
  }
  if (annMatch && method === 'DELETE') {
    await env.DB.prepare('DELETE FROM announcements WHERE id = ?').bind(annMatch[1]).run();
    return json({ ok: true });
  }

  return err('Not found', 404);
}
