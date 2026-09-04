-- PayHub V4 logical schema (SQLite-compatible starter schema)
-- The Node server auto-creates these tables on startup.
-- For production, migrate to PostgreSQL and use UUID/NUMERIC types.

CREATE TABLE merchants (...);
CREATE TABLE api_keys (...);
CREATE TABLE orders (...);
CREATE TABLE wallet_transactions (...);
CREATE TABLE webhook_logs (...);

-- V8 payment channel configuration
CREATE TABLE IF NOT EXISTS payment_channels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  merchant_id INTEGER NOT NULL,
  channel_code TEXT NOT NULL,
  display_name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  config_json TEXT NOT NULL DEFAULT '{}',
  webhook_url TEXT NOT NULL DEFAULT '',
  callback_secret TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(merchant_id, channel_code)
);

-- V9 merchant API credentials
CREATE TABLE IF NOT EXISTS merchant_api_credentials(id INTEGER PRIMARY KEY AUTOINCREMENT,merchant_id INTEGER NOT NULL UNIQUE,api_key TEXT NOT NULL UNIQUE,api_secret_hash TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_request_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,merchant_id INTEGER,api_key TEXT,method TEXT,path TEXT,order_no TEXT,request_id TEXT,signature_valid INTEGER NOT NULL DEFAULT 0,status_code INTEGER,created_at TEXT NOT NULL);

-- V10 wallet ledger and webhook delivery queue
CREATE TABLE IF NOT EXISTS wallet_ledger (
 id INTEGER PRIMARY KEY AUTOINCREMENT, merchant_id INTEGER NOT NULL, order_no TEXT,
 type TEXT NOT NULL, amount REAL NOT NULL, fee REAL NOT NULL DEFAULT 0,
 net_amount REAL NOT NULL, balance_before REAL NOT NULL DEFAULT 0,
 balance_after REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'posted',
 remark TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
 UNIQUE(merchant_id,order_no,type)
);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
 id INTEGER PRIMARY KEY AUTOINCREMENT, merchant_id INTEGER NOT NULL, order_no TEXT NOT NULL,
 event_type TEXT NOT NULL, target_url TEXT NOT NULL, payload TEXT NOT NULL,
 signature TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
 last_error TEXT NOT NULL DEFAULT '', next_retry_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
