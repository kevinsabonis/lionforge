-- Inventory change log: one row per change to the product catalog.
-- source: 'admin' (admin panel save), 'order' (stock deducted by an order),
--         'baseline' (starting stock recorded when the log was created).
-- actor:  admin email, 'Order #N', or '' for baseline rows.
-- change: stock | price | visibility | name | variant_added | variant_removed
--         | product_added | product_removed | baseline
CREATE TABLE IF NOT EXISTS inventory_log (
  id           TEXT PRIMARY KEY,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  source       TEXT NOT NULL,
  actor        TEXT NOT NULL DEFAULT '',
  product_id   INTEGER,
  product_name TEXT NOT NULL DEFAULT '',
  variant      TEXT NOT NULL DEFAULT '',
  change       TEXT NOT NULL,
  old_value    TEXT NOT NULL DEFAULT '',
  new_value    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_inventory_log_created ON inventory_log (created_at);
