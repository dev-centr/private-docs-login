import { test } from "node:test"
import assert from "node:assert/strict"
import { generateKeyPairSync } from "node:crypto"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import { createIssuer } from "../src/issuer.mjs"
import { createGithubForge, githubManifest, organizationsFromInstallations } from "../src/github.mjs"
import { createGitlabForge, groupsFromMemberLists } from "../src/gitlab.mjs"
import { describeConfig, loadRuntimeConfig } from "../src/config.mjs"
import { parseSdl } from "../src/sdl.mjs"
import { exchangeManifestCode, manifestForm } from "../src/manifest.mjs"
import { gitlabSetupText } from "../src/gitlab-setup.mjs"

const root = dirname(fileURLToPath(import.meta.url))

async function keys() {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
  publicJwk.alg = "RS256"
  publicJwk.use = "sig"
  publicJwk.kid = "test"
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk }
}

function clients() {
  return [{ id: "rp", secret: "secret", redirectUris: ["https://rp.example/callback"] }]
}

function payloadOf(jwt) {
  const part = jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")
  return JSON.parse(Buffer.from(part, "base64").toString("utf8"))
}

async function signIn(app, { forge, instance, callbackPath }) {
  const params = new URLSearchParams({
    client_id: "rp",
    redirect_uri: "https://rp.example/callback",
    response_type: "code",
    scope: "openid",
    state: "from-rp",
    nonce: "n-1",
    forge,
  })
  if (instance) params.set("instance", instance)
  const start = await app.handle(new Request(`https://login.example.com/authorize?${params}`))
  assert.equal(start.status, 200)
  const acceptance = await start.text()
  assert.match(acceptance, /stop and give your organization admin this message/)
  assert.match(acceptance, /https:\/\/docs\.devcentr\.org\/tools\/private-docs-login\/how-to\//)
  const next = new URL(`https://login.example.com/authorize?${params}`)
  next.searchParams.set("accepted", "1")
  const redirect = await app.handle(new Request(next))
  assert.equal(redirect.status, 302)
  const state = new URL(redirect.headers.get("location")).searchParams.get("state")
  const back = await app.handle(new Request(`https://login.example.com${callbackPath}?code=abc&state=${state}`))
  return back
}

async function tokenFor(app, back) {
  assert.equal(back.status, 302)
  const code = new URL(back.headers.get("location")).searchParams.get("code")
  const token = await app.handle(new Request("https://login.example.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://rp.example/callback",
      client_id: "rp",
      client_secret: "secret",
    }),
  }))
  assert.equal(token.status, 200)
  const body = await token.json()
  return payloadOf(body.id_token)
}

function githubFetch(installations) {
  return async (url) => {
    const u = String(url)
    if (u.includes("/login/oauth/access_token")) return Response.json({ access_token: "ght" })
    if (u.includes("/user/installations")) return Response.json({ installations })
    if (u.endsWith("/user")) return Response.json({ id: 7, login: "ada" })
    return new Response("missing", { status: 404 })
  }
}

function gitlabFetch(groups, membersById) {
  return async (url) => {
    const u = String(url)
    if (u.includes("/oauth/token")) return Response.json({ access_token: "glt" })
    if (u.includes("/members/all")) {
      const id = u.match(/\/groups\/(\d+)\//)[1]
      return Response.json(membersById[id] || [])
    }
    if (u.includes("/api/v4/groups?")) return Response.json(groups)
    if (u.includes("/api/v4/user")) return Response.json({ id: 9, username: "ada" })
    return new Response("missing", { status: 404 })
  }
}

test("discovery document uses the configured issuer and groups claim", async () => {
  const material = await keys()
  const app = createIssuer({
    ...material,
    issuer: "https://login.example.com",
    groupsClaim: "teams",
    clients: clients(),
    kid: "test",
  })
  const res = await app.handle(new Request("https://login.example.com/.well-known/openid-configuration"))
  const doc = await res.json()
  assert.equal(doc.issuer, "https://login.example.com")
  assert.equal(doc.authorization_endpoint, "https://login.example.com/authorize")
  assert.equal(doc.token_endpoint, "https://login.example.com/token")
  assert.equal(doc.jwks_uri, "https://login.example.com/jwks")
  assert.ok(doc.claims_supported.includes("teams"))
  assert.ok(doc.claims_supported.includes("forge"))
})

test("config file supplies issuer and groups claim", () => {
  const example = parseSdl(readFileSync(join(root, "..", "config", "issuer.example.sdl"), "utf8"))
  const described = describeConfig(example)
  assert.equal(described.issuer, "https://login.example.com")
  assert.equal(described.groupsClaim, "groups")
  const custom = describeConfig(parseSdl("issuer \"https://issuer.example\"\ngroups-claim \"teams\"\n"))
  assert.equal(custom.issuer, "https://issuer.example")
  assert.equal(custom.groupsClaim, "teams")
})

test("groups claim is built from this app's organization installations", async () => {
  const listed = organizationsFromInstallations({
    installations: [
      { app_id: 42, account: { login: "dev-centr", type: "Organization" } },
      { app_id: 42, account: { login: "ada", type: "User" } },
      { app_id: 99, account: { login: "other", type: "Organization" } },
    ],
  }, 42)
  assert.deepEqual(listed, ["dev-centr"])
  const material = await keys()
  const github = createGithubForge({
    fetchImpl: githubFetch([
      { app_id: 42, account: { login: "dev-centr", type: "Organization" } },
      { app_id: 42, account: { login: "ada", type: "User" } },
      { app_id: 99, account: { login: "other", type: "Organization" } },
    ]),
    clientId: "cid",
    clientSecret: "csecret",
    appId: "42",
    apiBase: "https://api.github.com",
    webBase: "https://github.com",
    slug: "private-docs-login",
  })
  const app = createIssuer({
    ...material,
    issuer: "https://login.example.com",
    groupsClaim: "teams",
    clients: clients(),
    kid: "test",
    github,
  })
  const back = await signIn(app, { forge: "github", callbackPath: "/github/callback" })
  const payload = await tokenFor(app, back)
  assert.deepEqual(payload.teams, ["github:github.com:dev-centr"])
  assert.equal(payload.forge, "github")
  assert.equal(payload.nonce, "n-1")
  assert.equal(payload.iss, "https://login.example.com")
})

test("a user with zero installations is refused", async () => {
  const material = await keys()
  const github = createGithubForge({
    fetchImpl: githubFetch([]),
    clientId: "cid",
    clientSecret: "csecret",
    appId: 42,
    apiBase: "https://api.github.com",
    webBase: "https://github.com",
    slug: "private-docs-login",
  })
  const app = createIssuer({ ...material, issuer: "https://login.example.com", clients: clients(), kid: "test", github })
  const back = await signIn(app, { forge: "github", callbackPath: "/github/callback" })
  assert.equal(back.status, 403)
  const html = await back.text()
  assert.match(html, /Private Docs Login/)
  assert.match(html, /install/i)
  assert.equal(back.headers.get("location"), null)
})

test("redirect URI must match the registered client", async () => {
  const material = await keys()
  const app = createIssuer({ ...material, issuer: "https://login.example.com", clients: clients(), kid: "test" })
  const res = await app.handle(new Request("https://login.example.com/authorize?client_id=rp&redirect_uri=https%3A%2F%2Fevil.example%2Fcallback&response_type=code&scope=openid"))
  assert.equal(res.status, 400)
  assert.match(await res.text(), /not registered/)
})

test("an opted-in GitLab group is included and a group without the opt-in user is excluded", async () => {
  const groups = [
    { id: 1, full_path: "opted/in" },
    { id: 2, full_path: "not/opted" },
  ]
  const members = {
    1: [{ username: "private-docs-login" }, { username: "ada" }],
    2: [{ username: "ada" }, { username: "private-docs-login-extra" }],
  }
  assert.deepEqual(groupsFromMemberLists(groups, members, "private-docs-login"), ["opted/in"])
  const material = await keys()
  const gitlab = createGitlabForge({
    fetchImpl: gitlabFetch(groups, members),
    instanceUrl: "https://gitlab.example.com",
    clientId: "gid",
    clientSecret: "gsecret",
    optInUsername: "private-docs-login",
  })
  const app = createIssuer({
    ...material,
    issuer: "https://login.example.com",
    groupsClaim: "groups",
    clients: clients(),
    kid: "test",
    gitlab: [gitlab],
  })
  const back = await signIn(app, {
    forge: "gitlab",
    instance: "https://gitlab.example.com",
    callbackPath: "/gitlab/callback",
  })
  const payload = await tokenFor(app, back)
  assert.deepEqual(payload.groups, ["gitlab:gitlab.example.com:opted/in"])
  assert.equal(payload.forge, "gitlab")
  assert.equal(payload.groups.includes("gitlab:gitlab.example.com:not/opted"), false)
})

test("zero opted-in GitLab groups is a refusal", async () => {
  const material = await keys()
  const gitlab = createGitlabForge({
    fetchImpl: gitlabFetch(
      [{ id: 2, full_path: "not/opted" }],
      { 2: [{ username: "ada" }] },
    ),
    instanceUrl: "https://gitlab.example.com",
    clientId: "gid",
    clientSecret: "gsecret",
    optInUsername: "private-docs-login",
  })
  const app = createIssuer({
    ...material,
    issuer: "https://login.example.com",
    clients: clients(),
    kid: "test",
    gitlab: [gitlab],
  })
  const back = await signIn(app, {
    forge: "gitlab",
    instance: "https://gitlab.example.com",
    callbackPath: "/gitlab/callback",
  })
  assert.equal(back.status, 403)
  const html = await back.text()
  assert.match(html, /not opted in/)
  assert.match(html, /private-docs-login/)
  assert.match(html, /email address does not/)
})

test("GitHub manifest names the app and asks only for member read", () => {
  const manifest = githubManifest({
    issuer: "https://login.example.com",
    setupOrigin: "http://127.0.0.1:8765",
  })
  assert.equal(manifest.name, "Private Docs Login")
  assert.match(manifest.description, /A login provider for private documentation sites that use OpenID Connect/)
  assert.match(manifest.description, /GitHub and GitLab org members sign in through their org's installation/)
  assert.ok(manifest.description.length <= 350)
  assert.deepEqual(manifest.default_permissions, { members: "read" })
  assert.equal(JSON.stringify(manifest).includes("contents"), false)
  assert.equal(JSON.stringify(manifest).includes("email"), false)
  assert.equal(manifest.callback_urls[0], "https://login.example.com/github/callback")
  const html = manifestForm({
    webBase: "https://github.com",
    owner: "dev-centr",
    manifest,
  })
  assert.match(html, /organizations\/dev-centr\/settings\/apps\/new/)
  assert.match(html, /Private Docs Login/)
  assert.match(html, /login provider for private documentation sites/)
})

test("post-install setup page states what the installation allows", async () => {
  const material = await keys()
  const app = createIssuer({ ...material, issuer: "https://login.example.com", clients: clients(), kid: "test" })
  const res = await app.handle(new Request("https://login.example.com/github/setup"))
  assert.equal(res.status, 200)
  assert.match(res.headers.get("content-type"), /text\/html/)
  const html = await res.text()
  assert.match(html, /name members of this organization in tokens/)
  assert.match(html, /Each site still checks for its own organization/)
  assert.match(html, /pass through the publisher's host/)
  assert.match(html, /login provider for OpenID Connect-enabled private sites/)
  assert.match(html, /An Antora site behind Cloudflare Access/)
  assert.match(html, /https:\/\/docs\.devcentr\.org\/tools\/private-docs-login\/how-to\//)
})

test("the forge chooser states the shared-issuer limit before GitHub", async () => {
  const material = await keys()
  const github = createGithubForge({
    fetchImpl: githubFetch([]),
    clientId: "cid",
    clientSecret: "csecret",
    appId: 42,
    apiBase: "https://api.github.com",
    webBase: "https://github.com",
    slug: "private-docs-login",
  })
  const gitlab = createGitlabForge({
    fetchImpl: gitlabFetch([], {}),
    instanceUrl: "https://gitlab.example.com",
    clientId: "gid",
    clientSecret: "gsecret",
    optInUsername: "private-docs-login",
  })
  const app = createIssuer({
    ...material,
    issuer: "https://login.example.com",
    clients: clients(),
    kid: "test",
    github,
    gitlab: [gitlab],
  })
  const res = await app.handle(new Request("https://login.example.com/authorize?client_id=rp&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&response_type=code&scope=openid"))
  assert.equal(res.status, 200)
  const html = await res.text()
  assert.match(html, /stop and give your organization admin this message/)
  assert.match(html, /name="accepted" value="1"/)
  assert.match(html, /login provider for private documentation sites/)
  assert.match(html, /An Antora site behind Cloudflare Access/)
  assert.match(html, /https:\/\/docs\.devcentr\.org\/tools\/private-docs-login\/how-to\//)
})

test("GitLab setup names the app, the scope, and the opt-in user", async () => {
  const text = await gitlabSetupText({
    instance: {
      instanceUrl: "https://gitlab.example.com",
      ownerGroup: "antora-supplemental",
      optInUsername: "private-docs-login",
    },
    issuer: "https://login.example.com",
    fetchImpl: async () => new Response("missing", { status: 404 }),
  })
  assert.match(text, /https:\/\/gitlab.example.com\/groups\/antora-supplemental\/-\/settings\/applications/)
  assert.match(text, /Name: Private Docs Login/)
  assert.match(text, /read_api/)
  assert.match(text, /private-docs-login/)
  assert.match(text, /No GitLab group named antora-supplemental/)
})

test("the old environment prefix does not satisfy PRIVATE_DOCS_LOGIN_ names", async () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
  const pem = privateKey.export({ type: "pkcs8", format: "pem" })
  const dir = mkdtempSync(join(tmpdir(), "private-docs-login-"))
  const pemPath = join(dir, "signing.pem")
  writeFileSync(pemPath, pem)
  const raw = parseSdl(`
issuer "https://login.example.com"
signing-key {
  pem-path-env "PRIVATE_DOCS_LOGIN_SIGNING_KEY_PATH"
}
listen { host "127.0.0.1" port 4180 }
github {
  owner "example"
  app-id-env "PRIVATE_DOCS_LOGIN_GITHUB_APP_ID"
  client-id-env "PRIVATE_DOCS_LOGIN_GITHUB_CLIENT_ID"
  client-secret-env "PRIVATE_DOCS_LOGIN_GITHUB_CLIENT_SECRET"
}
`)
  try {
    await assert.rejects(
      loadRuntimeConfig(raw, {
        ANTORA_PRIVATE_DOCS_SIGNING_KEY_PATH: pemPath,
        ANTORA_PRIVATE_DOCS_LISTEN: "10.0.0.1:4190",
        ANTORA_PRIVATE_DOCS_GITHUB_APP_ID: "42",
        ANTORA_PRIVATE_DOCS_GITHUB_CLIENT_ID: "cid",
        ANTORA_PRIVATE_DOCS_GITHUB_CLIENT_SECRET: "csecret",
      }),
      /PRIVATE_DOCS_LOGIN_SIGNING_KEY_PATH/,
    )
    const runtime = await loadRuntimeConfig(raw, {
      PRIVATE_DOCS_LOGIN_SIGNING_KEY_PATH: pemPath,
      PRIVATE_DOCS_LOGIN_LISTEN: "10.0.0.1:4190",
      PRIVATE_DOCS_LOGIN_GITHUB_APP_ID: "42",
      PRIVATE_DOCS_LOGIN_GITHUB_CLIENT_ID: "cid",
      PRIVATE_DOCS_LOGIN_GITHUB_CLIENT_SECRET: "csecret",
    })
    assert.equal(runtime.listenHost, "10.0.0.1")
    assert.equal(runtime.listenPort, 4190)
    assert.equal(runtime.kid, "private-docs-login-1")
    assert.equal(runtime.github.slug, "private-docs-login")
    assert.equal(runtime.github.appId, "42")
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("manifest exchange expects the app name Private Docs Login", async () => {
  await assert.rejects(
    exchangeManifestCode(async () => Response.json({ name: "Other App" }), "code"),
    /not Private Docs Login/,
  )
  const body = await exchangeManifestCode(async () => Response.json({ name: "Private Docs Login", id: 7 }), "code")
  assert.equal(body.name, "Private Docs Login")
  assert.equal(body.id, 7)
})
