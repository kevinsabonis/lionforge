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
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
  });

const err = (msg, status = 400) => json({ error: msg }, status);

// ── Auth middleware ────────────────────────────────────────────────────────

async function getUser(request, secret) {
  // Try cookie first, then Authorization: Bearer header (mobile fallback)
  const cookie = request.headers.get('Cookie') || '';
  const cookieMatch = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  if (cookieMatch) {
    const user = await jwtVerify(cookieMatch[1], secret);
    if (user) return user;
  }
  const auth = request.headers.get('Authorization') || '';
  const bearerMatch = auth.match(/^Bearer\s+(.+)$/i);
  if (bearerMatch) return jwtVerify(bearerMatch[1], secret);
  return null;
}

function sessionCookie(token) {
  return `session=${token}; HttpOnly; Secure; SameSite=Lax; Max-Age=604800; Path=/`;
}

function clearCookie() {
  return `session=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`;
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

      if (path === '/api/orders/next-num' && method === 'GET')
        return handleNextNum(env);

      // ── Shipping ─────────────────────────────────────────────────────────────
      const labelMatch = path.match(/^\/api\/admin\/orders\/([^/]+)\/create-label$/);
      if (labelMatch && method === 'POST') return await handleCreateLabel(request, env, labelMatch[1]);

      // ── Admin routes ─────────────────────────────────────────────────────
      if (path.startsWith('/api/admin/')) return handleAdmin(request, env, path, method);

      return err('Not found', 404);
    } catch (e) {
      console.error(e);
      return err(e.message || 'Internal server error', 500);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(processNewOrders(env));
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

  // Log the event
  await env.DB.prepare('INSERT INTO login_events (id, email, event) VALUES (?, ?, ?)')
    .bind(crypto.randomUUID(), email.toLowerCase(), 'code_requested').run();

  // Send OTP email via Resend
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: 'Lion Forge Peptides <onboarding@resend.dev>',
        to: [email],
        subject: 'Your Lion Forge Peptides Sign-In Code',
        html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#060a18;color:#c8d4e8;border-radius:8px;">
          <h2 style="color:#e8a820;letter-spacing:0.05em;margin-bottom:8px;">LION FORGE PEPTIDES</h2>
          <p style="color:#6a7a9e;font-size:13px;margin-bottom:32px;">SIGN-IN CODE</p>
          <p style="font-size:15px;margin-bottom:16px;">Your sign-in code is:</p>
          <div style="font-size:40px;font-weight:700;letter-spacing:0.15em;color:#ffd060;background:#0d1535;padding:24px;border-radius:6px;text-align:center;">${code}</div>
          <p style="font-size:13px;color:#6a7a9e;margin-top:24px;">This code expires in 15 minutes. If you did not request this, you can safely ignore this email.</p>
        </div>`
      })
    });
  } catch(e) {
    console.error('Resend OTP error:', e.message);
  }

  return json({ ok: true });
}

async function handleVerifyCode(request, env) {
  const { email, code } = await request.json();
  if (!email || !code) return err('Email and code required');

  const row = await env.DB.prepare(
    "SELECT * FROM otp_codes WHERE email = ? AND code = ? AND used = 0 AND expires_at > datetime('now')"
  ).bind(email.toLowerCase(), String(code)).first();

  if (!row) {
    await env.DB.prepare('INSERT INTO login_events (id, email, event) VALUES (?, ?, ?)')
      .bind(crypto.randomUUID(), email.toLowerCase(), 'login_failed').run();
    return err('Invalid or expired code. Request a new one.', 401);
  }

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
  // Log successful login
  await env.DB.prepare('INSERT INTO login_events (id, email, event) VALUES (?, ?, ?)')
    .bind(crypto.randomUUID(), user.email, 'login_success').run();

  // Return token in body so mobile clients can use Bearer auth as cookie fallback
  return json({ uid: user.id, email: user.email, displayName: user.display_name, role: user.role, _token: token }, 200, {
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
  let uid = user ? user.uid : 'guest';
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

  // If placing as guest but email matches a known user, link to their account
  if (uid === 'guest' && email) {
    const knownUser = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
    if (knownUser) uid = knownUser.id;
  }

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

async function handleNextNum(env) {
  const row = await env.DB.prepare("SELECT value FROM config WHERE key = 'lastOrderNum'").first();
  return json({ orderNum: (row ? Number(row.value) : 53) + 1 });
}

async function handleGetOrders(request, env) {
  const user = await getUser(request, env.JWT_SECRET);
  if (!user) return err('Unauthenticated', 401);
  // Match by uid OR by email — catches orders placed on mobile where
  // the session cookie wasn't sent and the order was saved as guest.
  const { results } = await env.DB.prepare(
    'SELECT * FROM orders WHERE uid = ? OR (email = ? AND email != \'\') ORDER BY created_at DESC'
  ).bind(user.uid, user.email).all();
  // Deduplicate in case both conditions match the same row
  const seen = new Set();
  const unique = results.filter(o => { if (seen.has(o.id)) return false; seen.add(o.id); return true; });
  return json(unique.map(o => ({ ...o, items: JSON.parse(o.items) })));
}

// ── Admin handlers ─────────────────────────────────────────────────────────

async function handleAdmin(request, env, path, method) {
  const user = await getUser(request, env.JWT_SECRET);
  if (!user || user.role !== 'admin') return err('Forbidden', 403);

  if (path === '/api/admin/orders' && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT * FROM orders ORDER BY order_num DESC').all();
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

  if (path === '/api/admin/login-events' && method === 'GET') {
    const { results } = await env.DB.prepare(
      'SELECT * FROM login_events ORDER BY created_at DESC LIMIT 200'
    ).all();
    return json(results);
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

// ── EasyPost helpers ───────────────────────────────────────────────────────

const FROM_ADDRESS = {
  name:    'Lion Forge Peptides',
  street1: 'PO Box 514',
  city:    'Prosper',
  state:   'TX',
  zip:     '75078',
  country: 'US',
  phone:   '8009999999',
};

function parseShippingAddress(raw) {
  // Stored as "Street, City, State, Zip" or "Street, City, ST Zip"
  const parts = raw.split(',').map(p => p.trim()).filter(Boolean);
  if (parts.length >= 3) {
    const zip   = parts[parts.length - 1].replace(/\D/g, '').slice(0, 5);
    const state = parts[parts.length - 2].replace(/\d/g, '').trim().slice(-2).toUpperCase();
    const city  = parts[parts.length - 3];
    const street = parts.slice(0, parts.length - 3).join(', ') || parts[0];
    return { street1: street || parts[0], city, state, zip };
  }
  return { street1: raw, city: '', state: '', zip: '' };
}

async function easypost(path, body, apiKey) {
  const r = await fetch(`https://api.easypost.com/v2${path}`, {
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + btoa(apiKey.trim() + ':'),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    throw new Error(e?.error?.message || `EasyPost ${r.status}`);
  }
  return r.json();
}

// ── Create label handler ───────────────────────────────────────────────────

async function handleCreateLabel(request, env, orderId) {
  const user = await getUser(request, env.JWT_SECRET);
  if (!user || user.role !== 'admin') return err('Forbidden', 403);

  const { weightOz } = await request.json();
  if (!weightOz || weightOz < 1 || weightOz > 160)
    return err('Weight must be between 1 and 160 oz');

  const order = await env.DB.prepare('SELECT * FROM orders WHERE id = ?').bind(orderId).first();
  if (!order) return err('Order not found', 404);

  const toAddr = parseShippingAddress(order.address || '');

  // Create shipment with all USPS rates
  const shipment = await easypost('/shipments', {
    shipment: {
      to_address:   { name: order.display_name, ...toAddr, country: 'US' },
      from_address: FROM_ADDRESS,
      parcel:       { weight: weightOz, length: 9, width: 6, height: 2 },
    },
  }, env.EASYPOST_API_KEY);

  // Pick cheapest USPS rate
  const uspsRates = (shipment.rates || [])
    .filter(r => r.carrier === 'USPS')
    .sort((a, b) => parseFloat(a.rate) - parseFloat(b.rate));

  if (!uspsRates.length) return err('No USPS rates available for this shipment');
  const cheapest = uspsRates[0];

  // Buy the label
  const bought = await easypost(`/shipments/${shipment.id}/buy`, {
    rate: { id: cheapest.id },
  }, env.EASYPOST_API_KEY);

  // Log full EasyPost buy response for debugging
  console.log('EasyPost buy response:', JSON.stringify({ tracking_code: bought.tracking_code, tracker: bought.tracker, postage_label: bought.postage_label, selected_rate: bought.selected_rate }));

  // EasyPost returns tracking_code at top level after buy
  const tracking  = bought.tracking_code || bought.tracker?.tracking_code || '';
  const labelUrl  = bought.postage_label?.label_url || bought.postage_label?.label_pdf_url || '';
  const labelFile = bought.postage_label?.label_file_type || 'PNG';
  const carrier   = `USPS ${bought.selected_rate?.service || cheapest.service}`;
  const shippedAt = new Date().toISOString();

  // Update order to shipped
  await env.DB.prepare(
    'UPDATE orders SET status=?, carrier=?, tracking_number=?, shipped_at=?, label_url=? WHERE id=?'
  ).bind('shipped', carrier, tracking || '', shippedAt, labelUrl || '', orderId).run();

  // Email label to admin via EmailJS REST API
  if (labelUrl) {
    const itemsList = JSON.parse(order.items || '[]')
      .map(i => `${i.name} (${i.variant}) x${i.qty}`).join(', ');
    try {
      const emailRes = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          service_id:  'service_lvdwr4o',
          template_id: 'template_cxsl0hq',
          user_id:     'oV9_mb8asjyRBR1iX',
          template_params: {
            order_number:    `#${order.order_num}`,
            customer_name:   order.display_name,
            ship_to:         order.address,
            items_list:      itemsList,
            carrier,
            tracking_number: tracking,
            label_url:       labelUrl,
            to_email:        'support@lionforgepeptides.com',
          },
        }),
      });
      const emailBody = await emailRes.text();
      console.log('EmailJS label response:', emailRes.status, emailBody);
    } catch(e) {
      console.error('Label email error:', e.message);
    }
  }

  return json({ ok: true, tracking, carrier, labelUrl, rate: cheapest.rate, debug: { tracking_code: bought.tracking_code, postage_label: bought.postage_label } });
}

// ── Gmail cron handler ─────────────────────────────────────────────────────
// Runs on schedule, reads unread order emails, creates labels automatically.

async function processNewOrders(env) {
  // Get Gmail access token via OAuth2 refresh
  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id:     env.GMAIL_CLIENT_ID,
      client_secret: env.GMAIL_CLIENT_SECRET,
      refresh_token: env.GMAIL_REFRESH_TOKEN,
      grant_type:    'refresh_token',
    }),
  });
  if (!tokenRes.ok) { console.error('Gmail token refresh failed'); return; }
  const { access_token } = await tokenRes.json();

  // Search for unread Lion Forge order notification emails
  const searchRes = await fetch(
    'https://gmail.googleapis.com/gmail/v1/users/me/messages?q=from:support@lionforgepeptides.com+subject:"New+Order"+is:unread&maxResults=10',
    { headers: { Authorization: `Bearer ${access_token}` } }
  );
  if (!searchRes.ok) return;
  const { messages } = await searchRes.json();
  if (!messages?.length) return;

  for (const msg of messages) {
    try {
      // Get full email
      const msgRes = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}?format=full`,
        { headers: { Authorization: `Bearer ${access_token}` } }
      );
      const email = await msgRes.json();

      // Decode body
      const bodyPart = email.payload?.parts?.find(p => p.mimeType === 'text/plain')
                    || email.payload;
      const bodyB64  = bodyPart?.body?.data || '';
      const body     = atob(bodyB64.replace(/-/g, '+').replace(/_/g, '/'));

      // Parse order number
      const orderNumMatch = body.match(/Order #(\d+)/i) || email.payload?.headers
        ?.find(h => h.name === 'Subject')?.value?.match(/#(\d+)/);
      if (!orderNumMatch) continue;
      const orderNum = parseInt(orderNumMatch[1]);

      // Parse Ship To address
      const shipMatch = body.match(/Ship To[:\s]+([^\n]+)/i);
      if (!shipMatch) continue;
      const address = shipMatch[1].trim();

      // Parse customer name
      const nameMatch = body.match(/Name[:\s]+([^\n]+)/i);
      const name = nameMatch ? nameMatch[1].trim() : 'Customer';

      // Look up order in D1
      const order = await env.DB.prepare(
        'SELECT * FROM orders WHERE order_num = ? AND status = ?'
      ).bind(orderNum, 'pending').first();

      if (!order) {
        console.log(`Order #${orderNum} not found or already processed`);
        // Mark email as read anyway
        await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}/modify`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${access_token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ removeLabelIds: ['UNREAD'] }),
        });
        continue;
      }

      // Default weight 8oz — midpoint of typical range
      const weightOz = 8;
      const toAddr   = parseShippingAddress(order.address || address);

      // Create and buy EasyPost label
      const shipment = await easypost('/shipments', {
        shipment: {
          to_address:   { name: order.display_name || name, ...toAddr, country: 'US' },
          from_address: FROM_ADDRESS,
          parcel:       { weight: weightOz, length: 9, width: 6, height: 2 },
        },
      }, env.EASYPOST_API_KEY);

      const uspsRates = (shipment.rates || [])
        .filter(r => r.carrier === 'USPS')
        .sort((a, b) => parseFloat(a.rate) - parseFloat(b.rate));

      if (!uspsRates.length) { console.error(`No USPS rates for order #${orderNum}`); continue; }

      const bought = await easypost(`/shipments/${shipment.id}/buy`, {
        rate: { id: uspsRates[0].id },
      }, env.EASYPOST_API_KEY);

      const tracking  = bought.tracking_code;
      const carrier   = `USPS ${uspsRates[0].service}`;
      const shippedAt = new Date().toISOString();
      const labelUrl  = bought.postage_label?.label_url;

      // Update D1 order to shipped
      await env.DB.prepare(
        'UPDATE orders SET status=?, carrier=?, tracking_number=?, shipped_at=? WHERE id=?'
      ).bind('shipped', carrier, tracking, shippedAt, order.id).run();

      console.log(`Order #${orderNum} labelled: ${tracking} — ${labelUrl}`);

      // Mark email as read
      await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}/modify`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${access_token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ removeLabelIds: ['UNREAD'] }),
      });

    } catch (e) {
      console.error(`Error processing message ${msg.id}:`, e.message);
    }
  }
}
