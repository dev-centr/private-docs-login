import { test } from "node:test"
import assert from "node:assert/strict"
import { createIssuer } from "../src/issuer.mjs"
import { createGithubForge } from "../src/github.mjs"
import { parseBasicClient, secretsEqual } from "../src/codec.mjs"
import { memoryStores } from "../src/store.mjs"

const SECRET = "s3cr:et+/ü"
const CLIENT = "cloudflare-access"
const REDIRECT = "https://team.cloudflareaccess.com/cdn-cgi/access/callback"

function githubFetch() {
  return async (url) => {
    const u = String(url)
    if (u.includes("/login/oauth/access_token")) return Response.json({ access_token: "ght" })
    if (u.includes("/user/installations")) {
      return Response.json({ installations: [{ app_id: 42, account: { login: "dev-centr", type: "Organization" } }] })
    }
    if (u.includes("/user/emails")) return Response.json([{ email: "ada@example.com", primary: true, verified: true }])
    if (u.endsWith("/user")) return Response.json({ id: 7, login: "ada" })
    return new Response("missing", { status: 404 })
  }
}

async function app() {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
  return createIssuer({
    privateKey: pair.privateKey,
    publicJwk: { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", use: "sig", kid: "t" },
    kid: "t",
    issuer: "https://login.example.com",
    clients: [{ id: CLIENT, secret: SECRET, redirectUris: [REDIRECT] }],
    github: createGithubForge({
      webBase: "https://github.com", apiBase: "https://api.github.com", slug: "private-docs-login",
      appId: "42", clientId: "cid", clientSecret: "cs", fetchImpl: githubFetch(),
    }),
    stores: memoryStores(),
  })
}

async function codeFor(issuer) {
  const params = new URLSearchParams({
    client_id: CLIENT, redirect_uri: REDIRECT, response_type: "code", scope: "openid email",
    state: "rp", forge: "github", accepted: "1",
  })
  const start = await issuer.handle(new Request(`https://login.example.com/authorize?${params}`))
  const state = new URL(start.headers.get("location")).searchParams.get("state")
  const back = await issuer.handle(new Request(`https://login.example.com/github/callback?code=abc&state=${state}`))
  return new URL(back.headers.get("location")).searchParams.get("code")
}

// RFC 6749 2.3.1: form-urlencode each part, then base64 "id:secret".
function basic(id, secret) {
  const form = (v) => encodeURIComponent(v).replace(/%20/g, "+")
  return `Basic ${Buffer.from(`${form(id)}:${form(secret)}`, "utf8").toString("base64")}`
}

function tokenRequest(fields, headers = {}) {
  return new Request("https://login.example.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams({ grant_type: "authorization_code", redirect_uri: REDIRECT, ...fields }),
  })
}

test("client_secret_basic redeems a code, with RFC 6749 form-encoding of the secret", async () => {
  const issuer = await app()
  const code = await codeFor(issuer)
  const res = await issuer.handle(tokenRequest({ code }, { authorization: basic(CLIENT, SECRET) }))
  assert.equal(res.status, 200)
  assert.ok((await res.json()).id_token)
})

test("client_secret_basic may repeat a matching client_id in the body", async () => {
  const issuer = await app()
  const code = await codeFor(issuer)
  const res = await issuer.handle(tokenRequest({ code, client_id: CLIENT }, { authorization: basic(CLIENT, SECRET) }))
  assert.equal(res.status, 200)
})

test("client_secret_post still redeems a code", async () => {
  const issuer = await app()
  const code = await codeFor(issuer)
  const res = await issuer.handle(tokenRequest({ code, client_id: CLIENT, client_secret: SECRET }))
  assert.equal(res.status, 200)
})

test("a wrong Basic secret is invalid_client with a Basic challenge, and the code survives", async () => {
  const issuer = await app()
  const code = await codeFor(issuer)
  const res = await issuer.handle(tokenRequest({ code }, { authorization: basic(CLIENT, "wrong") }))
  assert.equal(res.status, 401)
  assert.equal((await res.json()).error, "invalid_client")
  assert.match(res.headers.get("www-authenticate"), /^Basic realm="private-docs-login"/)
  const retry = await issuer.handle(tokenRequest({ code }, { authorization: basic(CLIENT, SECRET) }))
  assert.equal(retry.status, 200, "a failed client authentication does not burn the code")
})

test("an unknown Basic client and a malformed Basic header are invalid_client with a challenge", async () => {
  const issuer = await app()
  for (const authorization of [basic("someone-else", SECRET), "Basic !!!not-base64", `Basic ${Buffer.from("no-colon").toString("base64")}`]) {
    const res = await issuer.handle(tokenRequest({ code: "x" }, { authorization }))
    assert.equal(res.status, 401, authorization)
    assert.equal((await res.json()).error, "invalid_client")
    assert.ok(res.headers.get("www-authenticate"))
  }
})

test("using Basic and a body client_secret together is invalid_request", async () => {
  const issuer = await app()
  const res = await issuer.handle(tokenRequest({ code: "x", client_secret: SECRET }, { authorization: basic(CLIENT, SECRET) }))
  assert.equal(res.status, 400)
  assert.equal((await res.json()).error, "invalid_request")
})

test("a body client_id that differs from the Basic client is invalid_request", async () => {
  const issuer = await app()
  const res = await issuer.handle(tokenRequest({ code: "x", client_id: "other" }, { authorization: basic(CLIENT, SECRET) }))
  assert.equal(res.status, 400)
  assert.equal((await res.json()).error, "invalid_request")
})

test("a wrong post secret is invalid_client without a Basic challenge", async () => {
  const issuer = await app()
  const res = await issuer.handle(tokenRequest({ code: "x", client_id: CLIENT, client_secret: "wrong" }))
  assert.equal(res.status, 401)
  assert.equal(res.headers.get("www-authenticate"), null)
})

test("discovery lists both client authentication methods", async () => {
  const issuer = await app()
  const doc = await (await issuer.handle(new Request("https://login.example.com/.well-known/openid-configuration"))).json()
  assert.deepEqual(doc.token_endpoint_auth_methods_supported, ["client_secret_basic", "client_secret_post"])
})

test("secretsEqual and parseBasicClient handle edge cases", async () => {
  assert.equal(await secretsEqual("abc", "abc"), true)
  assert.equal(await secretsEqual("abc", "abcd"), false)
  assert.equal(await secretsEqual("", ""), false)
  assert.equal(parseBasicClient("Bearer x"), null)
  assert.deepEqual(parseBasicClient(basic("a b", "c:d")), { id: "a b", secret: "c:d" })
  assert.deepEqual(parseBasicClient("Basic %%%"), { error: "malformed" })
})
