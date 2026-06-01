/**
 * Lion Forge Peptides — Cloudflare Worker
 * Handles /api/* routes; all other requests fall through to static assets.
 * Auth: passwordless email OTP — 6-digit code, 15-minute expiry.
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

    if (!path.startsWith('/api/')) {
      const response = await env.ASSETS.fetch(request);
      // Inject a client-side script into every HTML page that adds the Sign Out
      // button next to the logo if the user is logged in. Client-side so the
      // response stays cacheable at the edge regardless of session state.
      if (response.headers.get('Content-Type')?.includes('text/html')) {
        return new HTMLRewriter()
          .on('body', {
            element(el) {
              el.append(
                `<script>(function(){` +
                `fetch('/api/auth/me',{credentials:'include'})` +
                `.then(function(r){return r.ok?r.json():null})` +
                `.then(function(u){` +
                  `if(!u)return;` +
                  `var logo=document.querySelector('a.nav-logo');` +
                  `if(!logo)return;` +
                  `var b=document.createElement('button');` +
                  `b.textContent='Sign Out';` +
                  `b.style.cssText='margin-left:14px;background:none;border:1px solid rgba(255,255,255,0.12);border-radius:8px;padding:6px 14px;color:#6a7a9e;font-size:12px;font-family:Inter,sans-serif;cursor:pointer;letter-spacing:0.04em;vertical-align:middle;';` +
                  `b.onmouseover=function(){this.style.color='#ef4444';this.style.borderColor='rgba(239,68,68,0.35)';};` +
                  `b.onmouseout=function(){this.style.color='#6a7a9e';this.style.borderColor='rgba(255,255,255,0.12)';};` +
                  `b.onclick=function(){fetch('/api/auth/logout',{method:'POST',credentials:'include'}).finally(function(){window.location.href='index.html';});};` +
                  `logo.insertAdjacentElement('afterend',b);` +
                `}).catch(function(){});` +
                `})();</script>`,
                { html: true }
              );
            }
          })
          .transform(response);
      }
      return response;
    }

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
      if (path === '/api/auth/request-code' && method === 'POST')
        return handleRequestCode(request, env);
      if (path === '/api/auth/verify-code' && method === 'POST')
        return handleVerifyCode(request, env);
      if (path === '/api/auth/logout' && method === 'POST')
        return handleLogout();
      if (path === '/api/auth/me' && method === 'GET')
        return handleMe(request, env);
      if (path === '/api/users/me' && method === 'PUT')
        return handleUpdateProfile(request, env);

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

async function handleRequestCode(request, env) {
  const { email } = await request.json();
  if (!email || !email.includes('@')) return err('Valid email required');

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();

  // Replace any existing unused codes for this email
  await env.DB.prepare('DELETE FROM otp_codes WHERE email = ?').bind(email.toLowerCase()).run();
  await env.DB.prepare(
    'INSERT INTO otp_codes (id, email, code, expires_at) VALUES (?, ?, ?, ?)'
  ).bind(crypto.randomUUID(), email.toLowerCase(), code, expires).run();

  // Return the code — client sends it via EmailJS
  return json({ ok: true, code });
}

async function handleVerifyCode(request, env) {
  const { email, code } = await request.json();
  if (!email || !code) return err('Email and code required');

  const row = await env.DB.prepare(
    "SELECT * FROM otp_codes WHERE email = ? AND code = ? AND used = 0 AND expires_at > datetime('now')"
  ).bind(email.toLowerCase(), String(code)).first();

  if (!row) return err('Invalid or expired code. Request a new one.', 401);

  await env.DB.prepare('UPDATE otp_codes SET used = 1 WHERE id = ?').bind(row.id).run();

  // Find or auto-create user
  let user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  if (!user) {
    const id = crypto.randomUUID();
    const displayName = email.split('@')[0].replace(/[._-]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    await env.DB.prepare(
      'INSERT INTO users (id, email, password_hash, display_name) VALUES (?, ?, ?, ?)'
    ).bind(id, email.toLowerCase(), '', displayName).run();
    user = { id, email: email.toLowerCase(), display_name: displayName, role: 'customer' };
  }

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
  const row = await env.DB.prepare('SELECT address FROM users WHERE id = ?').bind(user.uid).first();
  return json({ uid: user.uid, email: user.email, displayName: user.displayName, role: user.role, address: row?.address || '' });
}

async function handleUpdateProfile(request, env) {
  const user = await getUser(request, env.JWT_SECRET);
  if (!user) return err('Unauthenticated', 401);
  const { displayName, address } = await request.json();

  const name = (displayName || '').trim().slice(0, 200);
  const addr = address !== undefined ? String(address).slice(0, 500) : null;

  if (name) await env.DB.prepare('UPDATE users SET display_name = ? WHERE id = ?').bind(name, user.uid).run();
  if (addr !== null) await env.DB.prepare('UPDATE users SET address = ? WHERE id = ?').bind(addr, user.uid).run();

  // If name changed, refresh JWT so subsequent /api/auth/me reflects it
  if (name) {
    const updated = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.uid).first();
    const token = await jwtSign(
      { uid: updated.id, email: updated.email, displayName: updated.display_name, role: updated.role, exp: Math.floor(Date.now() / 1000) + 604800 },
      env.JWT_SECRET
    );
    return json({ ok: true, displayName: updated.display_name }, 200, { 'Set-Cookie': sessionCookie(token) });
  }
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

  if (path === '/api/admin/orders' && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT * FROM orders ORDER BY created_at DESC').all();
    return json(results.map(o => ({ ...o, items: JSON.parse(o.items) })));
  }
  const orderMatch = path.match(/^\/api\/admin\/orders\/([^/]+)$/);
  if (orderMatch && method === 'PUT') {
    const body = await request.json();
    await env.DB.prepare(
      'UPDATE orders SET status = ?, carrier = ?, tracking_number = ?, shipped_at = ? WHERE id = ?'
    ).bind(
      body.status || 'pending',
      body.carrier || '',
      body.trackingNumber || '',
      body.shippedAt || '',
      orderMatch[1]
    ).run();
    return json({ ok: true });
  }

  if (path === '/api/admin/products' && method === 'GET') {
    const row = await env.DB.prepare('SELECT value FROM config WHERE key = ?').bind('products').first();
    return json(row ? JSON.parse(row.value) : { list: [] });
  }
  if (path === '/api/admin/products' && method === 'PUT') {
    const body = await request.json();
    await env.DB.prepare('UPDATE config SET value = ? WHERE key = ?').bind(JSON.stringify(body), 'products').run();
    return json({ ok: true });
  }

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
      "UPDATE announcements SET title = ?, content = ?, published = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(title, content, published ? 1 : 0, annMatch[1]).run();
    return json({ ok: true });
  }
  if (annMatch && method === 'DELETE') {
    await env.DB.prepare('DELETE FROM announcements WHERE id = ?').bind(annMatch[1]).run();
    return json({ ok: true });
  }

  return err('Not found', 404);
}
