import { test } from "node:test"
import assert from "node:assert/strict"
import { generateKeyPairSync } from "node:crypto"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import { DatabaseSync } from "node:sqlite"
import { createIssuer } from "../src/issuer.mjs"
import { createGithubForge, githubManifest } from "../src/github.mjs"
import { buildRuntime, describeConfig } from "../src/runtime.mjs"
import { parseSdl } from "../src/sdl.mjs"
import { manifestPlan } from "../src/manifest.mjs"
import { d1Stores, memoryStore, memoryStores, sqliteStores, STATE_SCHEMA } from "../src/store.mjs"
import { createWorker } from "../deploy/cloudflare/worker-core.mjs"

const root = dirname(fileURLToPath(import.meta.url))
const deployConfig = readFileSync(join(root, "..", "deploy", "cloudflare", "issuer.sdl"), "utf8")

function pem() {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
  return privateKey.export({ type: "pkcs8", format: "pem" })
}

function tempDir() {
  return mkdtempSync(join(tmpdir(), "private-docs-login-state-"))
}

// A D1 binding backed by node:sqlite, with D1's prepare().bind().first()/run() shape.
function fakeD1() {
  const db = new DatabaseSync(":memory:")
  db.exec(readFileSync(join(root, "..", "deploy", "cloudflare", "migrations", "0001_sign_in_state.sql"), "utf8"))
  return {
    db,
    prepare(sql) {
      return {
        bind(...params) {
          return {
            async first() { return db.prepare(sql).get(...params) ?? null },
            async run() { db.prepare(sql).run(...params); return { success: true } },
          }
        },
      }
    },
  }
}

function githubFetch() {
  return async (url) => {
    const u = String(url)
    if (u.includes("/login/oauth/access_token")) return Response.json({ access_token: "ght" })
    if (u.includes("/user/installations")) {
      return Response.json({ installations: [{ app_id: 42, account: { login: "dev-centr", type: "Organization" } }] })
    }
    if (u.endsWith("/user")) return Response.json({ id: 7, login: "ada" })
    return new Response("missing", { status: 404 })
  }
}

async function material(kid = "test") {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
  return { privateKey: pair.privateKey, publicJwk: { kty: "RSA", n: publicJwk.n, e: publicJwk.e, alg: "RS256", use: "sig", kid }, kid }
}

function issuerWith(stores, keys, now) {
  return createIssuer({
    ...keys,
    issuer: "https://login.example.com",
    clients: [{ id: "rp", secret: "secret", redirectUris: ["https://rp.example/callback"] }],
    github: createGithubForge({
      webBase: "https://github.com", apiBase: "https://api.github.com", slug: "private-docs-login",
      appId: "42", clientId: "cid", clientSecret: "cs", fetchImpl: githubFetch(),
    }),
    stores,
    now,
  })
}

async function startSignIn(app) {
  const params = new URLSearchParams({
    client_id: "rp", redirect_uri: "https://rp.example/callback", response_type: "code",
    scope: "openid", state: "from-rp", forge: "github", accepted: "1",
  })
  const res = await app.handle(new Request(`https://login.example.com/authorize?${params}`))
  assert.equal(res.status, 302)
  return new URL(res.headers.get("location")).searchParams.get("state")
}

async function finishSignIn(app, state) {
  const back = await app.handle(new Request(`https://login.example.com/github/callback?code=abc&state=${state}`))
  assert.equal(back.status, 302)
  return new URL(back.headers.get("location")).searchParams.get("code")
}

function tokenRequest(code) {
  return new Request("https://login.example.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", code, redirect_uri: "https://rp.example/callback",
      client_id: "rp", client_secret: "secret",
    }),
  })
}

test("memory adapter keeps rows until their TTL and gives each one out once", async () => {
  let clock = 1000
  const store = memoryStore(() => clock)
  await store.put("a", { n: 1 }, 50)
  assert.deepEqual(await store.peek("a"), { n: 1 })
  assert.deepEqual(await store.take("a"), { n: 1 })
  assert.equal(await store.take("a"), null)
  await store.put("b", { n: 2 }, 50)
  clock += 51
  assert.equal(await store.take("b"), null)
})

test("a sign-in started before a restart finishes after it with the SQLite adapter", async () => {
  const dir = tempDir()
  const path = join(dir, "state.sqlite")
  const keys = await material()
  try {
    const first = await sqliteStores(path)
    const state = await startSignIn(issuerWith(first, keys))
    first.close()

    const second = await sqliteStores(path)
    const app = issuerWith(second, keys)
    const code = await finishSignIn(app, state)
    const token = await app.handle(tokenRequest(code))
    assert.equal(token.status, 200)
    const body = await token.json()
    const replay = await app.handle(tokenRequest(code))
    assert.equal(replay.status, 400, "an authorization code is single use")
    const info = await app.handle(new Request("https://login.example.com/userinfo", {
      headers: { authorization: `Bearer ${body.access_token}` },
    }))
    assert.equal(info.status, 200)
    assert.deepEqual((await info.json()).groups, ["github:github.com:dev-centr"])
    second.close()
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("SQLite rows expire, and expired rows are swept on the next write", async () => {
  const dir = tempDir()
  let clock = 10_000
  try {
    const stores = await sqliteStores(join(dir, "state.sqlite"), () => clock)
    await stores.codes.put("old", { v: 1 }, 100)
    clock += 101
    assert.equal(await stores.codes.peek("old"), null)
    await stores.requests.put("new", { v: 2 }, 100)
    const { db } = await import("node:sqlite").then(({ DatabaseSync }) => ({ db: new DatabaseSync(join(dir, "state.sqlite")) }))
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM sign_in_state").get().n, 1)
    db.close()
    stores.close()
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("D1 adapter runs a full sign-in, and a code cannot be redeemed twice", async () => {
  const d1 = fakeD1()
  const app = issuerWith(d1Stores(d1), await material())
  const code = await finishSignIn(app, await startSignIn(app))
  assert.equal((await app.handle(tokenRequest(code))).status, 200)
  assert.equal((await app.handle(tokenRequest(code))).status, 400)
})

test("the migration and STATE_SCHEMA create the same table", () => {
  const a = new DatabaseSync(":memory:")
  a.exec(STATE_SCHEMA)
  const b = fakeD1().db
  const cols = (db) => db.prepare("PRAGMA table_info(sign_in_state)").all().map((row) => `${row.name}:${row.type}:${row.pk}`)
  assert.deepEqual(cols(a), cols(b))
})

test("/healthz reports storage and does not name secrets", async () => {
  const keys = await material("kid-1")
  const app = issuerWith(memoryStores(), keys)
  const ok = await app.handle(new Request("https://login.example.com/healthz"))
  assert.equal(ok.status, 200)
  const body = await ok.json()
  assert.deepEqual(body, { ok: true, issuer: "https://login.example.com", storage: "memory", state: "ok", kid: "kid-1" })
  const broken = memoryStores()
  broken.codes.ping = async () => { throw new Error("down") }
  const bad = await issuerWith(broken, keys).handle(new Request("https://login.example.com/healthz"))
  assert.equal(bad.status, 503)
  assert.equal((await bad.json()).state, "error")
})

test("JWKS publishes the current key and the previous keys after a rotation", async () => {
  const raw = parseSdl(`
issuer "https://login.example.com"
signing-key {
  pem-env "SIGNING"
  previous-jwks-env "PREVIOUS"
  kid "k2"
}
`)
  const old = await buildRuntime(parseSdl(`issuer "https://login.example.com"\nsigning-key { pem-env "SIGNING"\n kid "k1" }\n`), { SIGNING: pem() })
  const runtime = await buildRuntime(raw, { SIGNING: pem(), PREVIOUS: JSON.stringify({ keys: [old.publicJwk] }) })
  const app = createIssuer({ ...runtime, issuer: runtime.issuer, clients: [] })
  const res = await app.handle(new Request("https://login.example.com/jwks"))
  const { keys } = await res.json()
  assert.deepEqual(keys.map((key) => key.kid), ["k2", "k1"])
  assert.ok(keys.every((key) => !key.d), "no private material in JWKS")
  await assert.rejects(
    buildRuntime(raw, { SIGNING: pem(), PREVIOUS: JSON.stringify([{ ...old.publicJwk, d: "secret" }]) }),
    /private key material/,
  )
})

test("the signing key can come from PEM text, and a path-only host names the variable", async () => {
  const raw = parseSdl(`issuer "https://login.example.com"\nsigning-key { pem-env "PRIVATE_DOCS_LOGIN_SIGNING_KEY" }\n`)
  await assert.rejects(buildRuntime(raw, {}), /PRIVATE_DOCS_LOGIN_SIGNING_KEY/)
  const runtime = await buildRuntime(raw, { PRIVATE_DOCS_LOGIN_SIGNING_KEY: pem() })
  assert.equal(runtime.publicJwk.kty, "RSA")
  const pathOnly = parseSdl(`issuer "https://login.example.com"\nsigning-key { pem-path-env "KEY_PATH" }\n`)
  await assert.rejects(buildRuntime(pathOnly, { KEY_PATH: "/x.pem" }), /cannot read files/)
})

test("the DevCentr deploy config is login.devcentr.org, owned by dev-centr, with no secret values", () => {
  const raw = parseSdl(deployConfig)
  assert.equal(describeConfig(raw).issuer, "https://login.devcentr.org")
  assert.equal(raw.github.owner, "dev-centr")
  assert.doesNotMatch(deployConfig, /BEGIN [A-Z ]*PRIVATE KEY/)
  const plan = manifestPlan({ webBase: raw.github.web, owner: raw.github.owner, issuer: raw.issuer, setupOrigin: "http://127.0.0.1:8765" })
  assert.equal(plan.action, "https://github.com/organizations/dev-centr/settings/apps/new")
  assert.equal(plan.callbackUrl, "https://login.devcentr.org/github/callback")
  assert.equal(plan.setupUrl, "https://login.devcentr.org/github/setup")
  assert.equal(plan.redirectUrl, "http://127.0.0.1:8765/setup/github/callback")
  assert.deepEqual(plan.manifest, githubManifest({ issuer: "https://login.devcentr.org", setupOrigin: "http://127.0.0.1:8765" }))
})

test("the example config names dev-centr as the GitHub App owner", () => {
  const example = parseSdl(readFileSync(join(root, "..", "config", "issuer.example.sdl"), "utf8"))
  assert.equal(example.github.owner, "dev-centr")
})

test("manifest plan refuses a missing owner and a plain-http public issuer", () => {
  assert.throws(() => manifestPlan({ owner: "", issuer: "https://login.devcentr.org", setupOrigin: "http://127.0.0.1:8765" }), /github.owner/)
  assert.throws(() => manifestPlan({ owner: "dev-centr", issuer: "http://login.devcentr.org", setupOrigin: "http://127.0.0.1:8765" }), /not https/)
})

test("the Worker host serves discovery, JWKS, and /healthz from the deploy config with D1 state", async () => {
  const worker = createWorker({ config: deployConfig })
  const env = {
    PRIVATE_DOCS_LOGIN_STATE: fakeD1(),
    PRIVATE_DOCS_LOGIN_SIGNING_KEY: pem(),
    PRIVATE_DOCS_LOGIN_GITHUB_APP_ID: "42",
    PRIVATE_DOCS_LOGIN_GITHUB_CLIENT_ID: "cid",
    PRIVATE_DOCS_LOGIN_GITHUB_CLIENT_SECRET: "cs",
    PRIVATE_DOCS_LOGIN_CLIENT_CLOUDFLARE_ACCESS: "rp-secret",
  }
  const doc = await (await worker.fetch(new Request("https://login.devcentr.org/.well-known/openid-configuration"), env)).json()
  assert.equal(doc.authorization_endpoint, "https://login.devcentr.org/authorize")
  assert.equal(doc.token_endpoint, "https://login.devcentr.org/token")
  assert.equal(doc.jwks_uri, "https://login.devcentr.org/jwks")
  const jwks = await (await worker.fetch(new Request("https://login.devcentr.org/jwks"), env)).json()
  assert.equal(jwks.keys[0].kid, "private-docs-login-1")
  const health = await worker.fetch(new Request("https://login.devcentr.org/healthz"), env)
  assert.equal(health.status, 200)
  assert.equal((await health.json()).storage, "d1")
  const missing = await createWorker({ config: deployConfig }).fetch(new Request("https://login.devcentr.org/healthz"), { ...env, PRIVATE_DOCS_LOGIN_SIGNING_KEY: "" })
  assert.equal(missing.status, 503)
  assert.deepEqual(await missing.json(), { ok: false, state: "not-configured" })
})

test("the Worker secrets file is built from var/ and creates missing keys without printing them", async () => {
  const { buildWorkerSecrets } = await import("../deploy/cloudflare/secrets.mjs")
  const dir = tempDir()
  try {
    assert.throws(() => buildWorkerSecrets(dir), /github-app.json is missing/)
    const { writeFileSync } = await import("node:fs")
    writeFileSync(join(dir, "github-app.json"), JSON.stringify({ id: 42, client_id: "Iv1.x", client_secret: "s" }))
    const built = buildWorkerSecrets(dir)
    assert.deepEqual(built.created, ["var/signing.pem", "var/cloudflare-access-client-secret"])
    const secrets = JSON.parse(readFileSync(built.outPath, "utf8"))
    assert.equal(secrets.PRIVATE_DOCS_LOGIN_GITHUB_APP_ID, "42")
    const runtime = await buildRuntime(parseSdl(deployConfig), secrets)
    assert.equal(runtime.github.owner, "dev-centr")
    assert.equal(runtime.clients[0].redirectUris[0], "https://amdphreak.cloudflareaccess.com/cdn-cgi/access/callback")
    assert.deepEqual(buildWorkerSecrets(dir).created, [], "existing keys are kept, so JWKS stays stable")
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
