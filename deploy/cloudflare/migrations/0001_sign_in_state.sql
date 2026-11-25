-- Sign-in state for the Worker host. Same table as STATE_SCHEMA in src/store.mjs.
CREATE TABLE IF NOT EXISTS sign_in_state (
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (kind, key)
);
CREATE INDEX IF NOT EXISTS sign_in_state_expires ON sign_in_state (expires_at);
