-- Lion Forge Peptides — D1 Schema

CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  email       TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  role        TEXT NOT NULL DEFAULT 'customer',
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS orders (
  id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  order_num    INTEGER NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending',
  uid          TEXT NOT NULL,
  display_name TEXT,
  email        TEXT,
  address      TEXT,
  payment_method TEXT,
  shipping_method TEXT,
  items        TEXT NOT NULL,
  subtotal     REAL,
  shipping     REAL,
  discount     REAL,
  discount_code TEXT,
  total        REAL,
  date         TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_orders_uid ON orders(uid);
CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at);

CREATE TABLE IF NOT EXISTS config (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
-- Seed initial config values
INSERT OR IGNORE INTO config (key, value) VALUES ('lastOrderNum', '53');
INSERT OR IGNORE INTO config (key, value) VALUES ('products', '{"list":[]}');

CREATE TABLE IF NOT EXISTS announcements (
  id        TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  title     TEXT NOT NULL DEFAULT '',
  content   TEXT NOT NULL DEFAULT '',
  published INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_announcements_created_at ON announcements(created_at);

CREATE TABLE IF NOT EXISTS reset_tokens (
  token      TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
