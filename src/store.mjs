// Sign-in state: pending authorize requests, one-time authorization codes, and access tokens.
// Every adapter exposes the same async interface, so the issuer does not know where rows live:
//   put(key, value, ttlMs), take(key) -> value | null (single use), peek(key) -> value | null, ping()
// memoryStore is for tests and a throwaway local run. sqlStore persists rows in SQLite (Node host,
// node:sqlite) or Cloudflare D1 (Worker host). Both use the table in STATE_SCHEMA.

export const STATE_SCHEMA = `CREATE TABLE IF NOT EXISTS sign_in_state (
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (kind, key)
);
CREATE INDEX IF NOT EXISTS sign_in_state_expires ON sign_in_state (expires_at);`

export const STATE_KINDS = ["requests", "codes", "accessTokens"]

export function memoryStore(now = () => Date.now()) {
  const rows = new Map()
  return {
    async put(key, value, ttlMs) {
      rows.set(key, { value: JSON.parse(JSON.stringify(value)), exp: now() + ttlMs })
    },
    async take(key) {
      const row = rows.get(key)
      if (!row) return null
      rows.delete(key)
      if (row.exp < now()) return null
      return row.value
    },
    async peek(key) {
      const row = rows.get(key)
      if (!row || row.exp < now()) return null
      return row.value
    },
    async ping() {
      return true
    },
  }
}

// executor: { run(sql, ...params), first(sql, ...params) -> row | null }, both async.
export function sqlStore(executor, kind, now = () => Date.now()) {
  if (!STATE_KINDS.includes(kind)) throw new Error(`Unknown state kind ${kind}`)
  return {
    async put(key, value, ttlMs) {
      const at = now()
      await executor.run("DELETE FROM sign_in_state WHERE expires_at < ?", at)
      await executor.run(
        "INSERT OR REPLACE INTO sign_in_state (kind, key, value, expires_at) VALUES (?, ?, ?, ?)",
        kind, key, JSON.stringify(value), at + ttlMs,
      )
    },
    async take(key) {
      // One statement deletes and returns the row, so two requests cannot both redeem one code.
      const row = await executor.first(
        "DELETE FROM sign_in_state WHERE kind = ? AND key = ? RETURNING value, expires_at",
        kind, key,
      )
      if (!row || Number(row.expires_at) < now()) return null
      return JSON.parse(row.value)
    },
    async peek(key) {
      const row = await executor.first(
        "SELECT value, expires_at FROM sign_in_state WHERE kind = ? AND key = ?",
        kind, key,
      )
      if (!row || Number(row.expires_at) < now()) return null
      return JSON.parse(row.value)
    },
    async ping() {
      await executor.first("SELECT COUNT(*) AS n FROM sign_in_state WHERE expires_at < ?", 0)
      return true
    },
  }
}

export function stateStores(make, label) {
  const stores = {}
  for (const kind of STATE_KINDS) stores[kind] = make(kind)
  stores.label = label
  return stores
}

export function memoryStores(now) {
  return stateStores(() => memoryStore(now), "memory")
}

// Cloudflare D1 binding. The table comes from the migration in deploy/cloudflare/migrations.
export function d1Executor(db) {
  return {
    async run(sql, ...params) {
      await db.prepare(sql).bind(...params).run()
    },
    async first(sql, ...params) {
      return (await db.prepare(sql).bind(...params).first()) || null
    },
  }
}

export function d1Stores(db, now) {
  const executor = d1Executor(db)
  return stateStores((kind) => sqlStore(executor, kind, now), "d1")
}

// Node host. node:sqlite ships with Node 22.13 and later; it is imported only when this adapter is used.
export async function sqliteExecutor(path) {
  const { DatabaseSync } = await import("node:sqlite")
  const db = new DatabaseSync(path)
  db.exec("PRAGMA journal_mode = WAL")
  db.exec(STATE_SCHEMA)
  return {
    db,
    async run(sql, ...params) {
      db.prepare(sql).run(...params)
    },
    async first(sql, ...params) {
      return db.prepare(sql).get(...params) || null
    },
    close() {
      db.close()
    },
  }
}

export async function sqliteStores(path, now) {
  const executor = await sqliteExecutor(path)
  const stores = stateStores((kind) => sqlStore(executor, kind, now), "sqlite")
  stores.close = () => executor.close()
  return stores
}
