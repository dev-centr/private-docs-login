import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import { createIssuer } from "../src/issuer.mjs"
import { createGithubForge } from "../src/github.mjs"
import { createGitlabForge } from "../src/gitlab.mjs"
import { ASSET_URLS } from "../src/assets.mjs"
import { badRedirectPage, chooserPage, connectAcceptancePage, forgeErrorPage, installSetupPage, noVerifiedEmailPage, refusalPage } from "../src/html.mjs"
import { buildAssets } from "../scripts/build-assets.mjs"

const root = join(dirname(fileURLToPath(import.meta.url)), "..")

async function issuer() {
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
    clients: [{ id: "rp", secret: "s", redirectUris: ["https://rp.example/callback"] }],
    github: createGithubForge({ webBase: "https://github.com", apiBase: "https://api.github.com", slug: "private-docs-login", appId: "1", clientId: "c", clientSecret: "s", fetchImpl: fetch }),
    gitlab: [createGitlabForge({ instanceUrl: "https://gitlab.example.com", optInUsername: "private-docs-login", clientId: "g", clientSecret: "s", fetchImpl: fetch })],
  })
}

const get = async (app, path) => app.handle(new Request(`https://login.example.com${path}`))

test("src/assets.generated.mjs is current with assets/", () => {
  assert.equal(readFileSync(join(root, "src", "assets.generated.mjs"), "utf8"), buildAssets(), "run node scripts/build-assets.mjs")
})

test("the issuer serves the stylesheet, font, and logo with immutable caching", async () => {
  const app = await issuer()
  const css = await get(app, ASSET_URLS.css)
  assert.equal(css.status, 200)
  assert.match(css.headers.get("content-type"), /^text\/css/)
  assert.match(css.headers.get("cache-control"), /immutable/)
  const text = await css.text()
  assert.ok(text.includes(ASSET_URLS.font), "the @font-face points at the hashed font path")
  assert.doesNotMatch(text, /https?:\/\//, "no remote font or stylesheet")
  const font = await get(app, ASSET_URLS.font)
  assert.equal(font.headers.get("content-type"), "font/woff2")
  assert.deepEqual(Buffer.from(await font.arrayBuffer()), readFileSync(join(root, "assets", "fonts", "space-grotesk-latin-wght-normal.woff2")))
  const glyph = await get(app, ASSET_URLS.glyph)
  assert.equal(glyph.headers.get("content-type"), "image/svg+xml")
  const favicon = await get(app, "/favicon.ico")
  assert.equal(favicon.status, 301)
  assert.equal(favicon.headers.get("location"), ASSET_URLS.favicon)
  assert.equal((await get(app, "/assets/pages.0000000000.css")).status, 404)
})

test("every issuer page uses the shared layout under a strict CSP", async () => {
  const app = await issuer()
  const pages = [
    await get(app, "/github/setup?installation_id=185715645&setup_action=install"),
    await get(app, "/authorize?client_id=rp&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid&forge=github"),
    await get(app, "/authorize?client_id=rp&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid"),
    await get(app, "/authorize?client_id=rp&redirect_uri=https%3A%2F%2Fevil.example%2Fcallback&scope=openid"),
  ]
  for (const res of pages) {
    const csp = res.headers.get("content-security-policy")
    assert.match(csp, /default-src 'none'/)
    assert.match(csp, /style-src 'self'/)
    assert.match(csp, /form-action 'self' https:\/\/github\.com https:\/\/gitlab\.example\.com/)
    assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/)
    assert.equal(res.headers.get("referrer-policy"), "no-referrer")
    const html = await res.text()
    assert.doesNotMatch(html, /<script/i, "no script")
    assert.doesNotMatch(html, /\sstyle=/i, "no inline style attribute")
    assert.doesNotMatch(html, /<style/i, "no inline style block")
    assert.ok(html.includes(`href="${ASSET_URLS.css}"`))
    assert.ok(html.includes(`href="${ASSET_URLS.favicon}"`))
    assert.match(html, /class="site-header"/)
    assert.doesNotMatch(html, /fonts\.googleapis|fonts\.gstatic/)
  }
  for (const res of [refusalPage({ forge: "github" }), noVerifiedEmailPage({ forge: "github" }), forgeErrorPage("GitHub"), badRedirectPage()]) {
    const html = await res.text()
    assert.match(html, /What to do next/)
    assert.match(html, /class="tone-stop"/)
  }
})

test("the setup page names the installation and the Access values, and nothing secret", async () => {
  const app = await issuer()
  const html = await (await get(app, "/github/setup?installation_id=185715645&setup_action=install")).text()
  assert.match(html, /Private Docs Login is installed/)
  assert.match(html, /<dt>Installation<\/dt><dd>185715645<\/dd>/)
  assert.match(html, /https:\/\/login\.example\.com\/authorize/)
  assert.match(html, /https:\/\/login\.example\.com\/token/)
  assert.match(html, /https:\/\/login\.example\.com\/jwks/)
  assert.match(html, /github:github\.com:&lt;your-organization&gt;/)
  assert.doesNotMatch(html, /client_secret|BEGIN [A-Z ]*KEY/)
  const requested = await (await get(app, "/github/setup?installation_id=1&setup_action=request")).text()
  assert.match(requested, /Your install request was sent/)
  const updated = await (await get(app, "/github/setup?setup_action=update")).text()
  assert.match(updated, /Private Docs Login is updated/)
})

test("interpolated values are escaped or dropped", async () => {
  const app = await issuer()
  const hostile = await (await get(app, `/github/setup?installation_id=${encodeURIComponent("<script>alert(1)</script>")}&setup_action=${encodeURIComponent("\"><img src=x>")}`)).text()
  assert.doesNotMatch(hostile, /<script>alert|<img src=x>/)
  assert.doesNotMatch(hostile, /<dt>Installation<\/dt>/, "a non-numeric installation id is not shown")
  assert.match(hostile, /Private Docs Login is installed/)
  const gitlab = await refusalPage({ forge: "gitlab", optInUsername: "<b>x</b>", instanceUrl: "https://g.example/\"><i>" }).text()
  assert.match(gitlab, /&lt;b&gt;x&lt;\/b&gt;/)
  assert.match(gitlab, /&quot;&gt;&lt;i&gt;/)
  const forge = await forgeErrorPage("<svg onload=x>").text()
  assert.match(forge, /&lt;svg onload=x&gt; did not complete sign-in/)
  const accept = await connectAcceptancePage({ state: "\"><script>x</script>", forge: "github" }).text()
  assert.match(accept, /value="&quot;&gt;&lt;script&gt;x&lt;\/script&gt;"/)
  const chooser = await chooserPage([{ forge: "gitlab", label: "<x>", instanceUrl: "https://g\"x", formId: "f\"1" }], {}).text()
  assert.doesNotMatch(chooser, /<x>|id="f"1"/)
  const setup = await installSetupPage({ issuer: "https://login.example.com/\"><b>" }).text()
  assert.doesNotMatch(setup, /"><b>/)
})

function luminance(hex) {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4))
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

function ratio(a, b) {
  const [x, y] = [luminance(a), luminance(b)].sort((m, n) => n - m)
  return (x + 0.05) / (y + 0.05)
}

function tokens(block) {
  return Object.fromEntries([...block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6})/gi)].map((m) => [m[1], m[2].toLowerCase()]))
}

test("light and dark token pairs meet WCAG AA contrast", () => {
  const css = readFileSync(join(root, "assets", "pages.css"), "utf8")
  const light = tokens(css.slice(css.indexOf(":root {"), css.indexOf("@media (prefers-color-scheme: dark)")))
  const dark = { ...light, ...tokens(css.slice(css.indexOf("@media (prefers-color-scheme: dark)"), css.indexOf("*, *::before"))) }
  for (const [name, set] of [["light", light], ["dark", dark]]) {
    for (const surface of ["surface-page", "surface-primary", "surface-muted"]) {
      assert.ok(ratio(set["text-primary"], set[surface]) >= 7, `${name} text on ${surface}`)
      assert.ok(ratio(set["text-muted"], set[surface]) >= 4.5, `${name} muted on ${surface}: ${ratio(set["text-muted"], set[surface]).toFixed(2)}`)
      assert.ok(ratio(set.accent, set[surface]) >= 4.5, `${name} accent link on ${surface}: ${ratio(set.accent, set[surface]).toFixed(2)}`)
    }
    assert.ok(ratio(set["on-accent"], set.accent) >= 4.5, `${name} button text`)
    assert.ok(ratio(set["on-accent"], set["accent-strong"]) >= 4.5, `${name} button hover text`)
    assert.ok(ratio(set.focus, set["surface-primary"]) >= 3, `${name} focus ring`)
    assert.ok(ratio(set["tone-stop"], set["surface-primary"]) >= 3, `${name} stop dot`)
  }
  assert.ok(ratio("#127266", "#ffffff") >= 4.5, "DevCentr teal on white")
})
