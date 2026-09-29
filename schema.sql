CREATE TABLE IF NOT EXISTS users (
  uuid TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  badge TEXT NOT NULL DEFAULT 'none',
  cosmetics TEXT NOT NULL DEFAULT '{}',
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_last_seen ON users(last_seen);
