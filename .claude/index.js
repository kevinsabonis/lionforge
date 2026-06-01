/**
 * Lion Forge — trusted checkout backend
 *
 * The browser is NEVER trusted for money or inventory. The client sends only
 * what it wants to buy (product id, variant index, quantity) plus shipping
 * choice and a discount code. This function looks up the real catalog from
 * Firestore with server credentials, recomputes the entire total itself
 * (items + shipping - discount), verifies and decrements stock, and writes
 * the order — all inside one atomic transaction.
 *
 * Callable name (client side): "placeOrder"
 */

const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

initializeApp();
const db = getFirestore();

// ── Business rules (server-authoritative) ──────────────────────────
const SHIPPING = { ground: 10, expedited: 15 };
const DISCOUNTS = { LION10: 0.10, FORGE20: 0.20, RESEARCH15: 0.15 };

// Stock at or above this is treated as "unlimited / bulk" — never blocked,
// never decremented. (Matches the shop UI, which shows >=100 as just "In stock".)
const UNLIMITED_THRESHOLD = 100;

const MAX_QTY_PER_ITEM = 999;
const MAX_DISTINCT_ITEMS = 100;

const round2 = (n) => Math.round(n * 100) / 100;

exports.placeOrder = onCall(async (request) => {
  const data = request.data || {};

  // Identify the buyer (logged in if available; guest otherwise).
  const uid = request.auth ? request.auth.uid : "guest";
  const authEmail = request.auth ? (request.auth.token.email || null) : null;

  // ── Validate the shape of what the browser sent ──────────────────
  const rawItems = Array.isArray(data.items) ? data.items : null;
  if (!rawItems || rawItems.length === 0) {
    throw new HttpsError("invalid-argument", "Your cart is empty.");
  }
  if (rawItems.length > MAX_DISTINCT_ITEMS) {
    throw new HttpsError("invalid-argument", "Too many items in one order.");
  }

  const requested = rawItems.map((it) => ({
    id: Number(it.id),
    variantIndex: Number(it.variantIndex),
    qty: Math.floor(Number(it.qty)),
  }));
  for (const r of requested) {
    const ok =
      Number.isFinite(r.id) &&
      Number.isInteger(r.variantIndex) && r.variantIndex >= 0 &&
      Number.isInteger(r.qty) && r.qty >= 1 && r.qty <= MAX_QTY_PER_ITEM;
    if (!ok) {
      throw new HttpsError(
        "invalid-argument",
        "A cart item was malformed. Please return to the shop and re-add your items."
      );
    }
  }

  // Customer/shipping details (labels only — not money-sensitive).
  const customer = data.customer || {};
  const displayName = String(customer.name || "").trim().slice(0, 200);
  const email = String(customer.email || authEmail || "").trim().slice(0, 200);
  const address = String(customer.address || "").trim().slice(0, 1000);
  if (!displayName || !address) {
    throw new HttpsError("invalid-argument", "A name and shipping address are required.");
  }

  const shippingMethod = (String(data.shippingMethod || "ground").toLowerCase() === "expedited")
    ? "expedited" : "ground";
  const discountCode = String(data.discountCode || "").trim().toUpperCase();
  const paymentMethod = String(data.paymentMethod || "").slice(0, 40);
  const clientOrderNum = Number(data.orderNum);

  const productsRef = db.doc("config/products");
  const settingsRef = db.doc("config/settings");

  // ── Validate prices + stock and write the order, atomically ──────
  const result = await db.runTransaction(async (tx) => {
    // All reads first.
    const [prodSnap, settingsSnap] = await Promise.all([
      tx.get(productsRef),
      tx.get(settingsRef),
    ]);

    if (!prodSnap.exists) {
      throw new HttpsError("failed-precondition", "Product catalog is unavailable.");
    }
    const list = prodSnap.data().list || [];
    const byId = new Map(list.map((p) => [Number(p.id), p]));

    let subtotal = 0;
    const lineItems = [];

    for (const r of requested) {
      const product = byId.get(r.id);
      if (!product) {
        throw new HttpsError("not-found", "An item in your cart is no longer available.");
      }
      if (product.hidden === true) {
        throw new HttpsError("failed-precondition", `${product.name} is not currently available.`);
      }
      const variant = product.variants && product.variants[r.variantIndex];
      if (!variant) {
        throw new HttpsError("not-found", `A selected option for ${product.name} is no longer available.`);
      }
      const stock = Number(variant.stock);
      const unlimited = Number.isFinite(stock) && stock >= UNLIMITED_THRESHOLD;
      if (!unlimited) {
        if (!Number.isFinite(stock) || stock < r.qty) {
          throw new HttpsError(
            "failed-precondition",
            `${product.name} (${variant.label}) only has ${Number.isFinite(stock) ? stock : 0} in stock.`
          );
        }
      }

      // Price comes from the database, never the browser.
      const unitPrice = Number(variant.price);
      const lineTotal = round2(unitPrice * r.qty);
      subtotal += lineTotal;

      lineItems.push({
        id: r.id,
        variantIndex: r.variantIndex,
        name: product.name,
        variant: variant.label,
        qty: r.qty,
        price: unitPrice,
        lineTotal,
      });
    }
    subtotal = round2(subtotal);

    // Shipping + discount from server rules — not the browser.
    const shipping = SHIPPING[shippingMethod];
    const discountRate = DISCOUNTS[discountCode] || 0;
    const discount = round2(subtotal * discountRate);
    const total = Math.max(0, round2(subtotal + shipping - discount));

    // Decrement stock for finite-stock variants only.
    const newList = list.map((p) => {
      const pid = Number(p.id);
      const hits = requested.filter((r) => r.id === pid);
      if (hits.length === 0) return p;
      const variants = p.variants.map((v, idx) => {
        const hit = hits.find((r) => r.variantIndex === idx);
        if (!hit) return v;
        const s = Number(v.stock);
        if (Number.isFinite(s) && s >= UNLIMITED_THRESHOLD) return v; // unlimited
        return { ...v, stock: s - hit.qty };
      });
      return { ...p, variants };
    });

    // Order number: use the client-reserved one if valid, else reserve here.
    let orderNum = clientOrderNum;
    if (!Number.isFinite(orderNum)) {
      const last = settingsSnap.exists ? Number(settingsSnap.data().lastOrderNum) || 53 : 53;
      orderNum = last + 1;
      tx.set(settingsRef, { lastOrderNum: orderNum }, { merge: true });
    }

    const orderRef = db.collection("orders").doc();
    const order = {
      orderNum,
      status: "pending",
      items: lineItems,
      subtotal,
      shipping,
      shippingMethod: shippingMethod === "expedited" ? "Expedited" : "Ground",
      discount,
      discountCode: discountRate ? discountCode : "",
      paymentMethod,
      address,
      total,
      displayName,
      email,
      uid,
      date: new Date().toISOString(),
      createdAt: FieldValue.serverTimestamp(),
    };

    // All writes.
    tx.set(productsRef, { list: newList });
    tx.set(orderRef, order);

    return { orderId: orderRef.id, orderNum, items: lineItems, subtotal, shipping, discount, total };
  });

  return result;
});
