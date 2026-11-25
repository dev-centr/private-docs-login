#!/usr/bin/env node
// Local preview of every page the issuer serves, with a stand-in forge so no GitHub app or secret is
// needed. Not a host: it signs with a throwaway key and keeps state in memory.
//   node scripts/preview.mjs [--port 4199]
// Pages: /github/setup?installation_id=185715645&setup_action=install, /authorize (acceptance),
// /preview/not-installed, /preview/no-email, /preview/error, /preview/bad-redirect, /preview/chooser
import { createServer } from "node:http"
import { createIssuer } from "../src/issuer.mjs"

const port = Number(process.argv[process.argv.indexOf("--port") + 1] || 4199) || 4199
const base = `http://127.0.0.1:${port}`
const pair = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"],
)
const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
let mode = "ok"
const forge = {
  id: "github",
  label: "GitHub",
  host: "github.com",
  installUrl: "https://github.com/apps/private-docs-login/installations/new",
  async authorizationUrl({ redirectUri, state }) { return `${redirectUri}?code=preview&state=${state}` },
  async complete() {
    if (mode === "error") throw new Error("preview failure")
    if (mode === "not-installed") return { subject: "1", username: "ada", email: "ada@example.com", emailVerified: true, groups: [] }
    if (mode === "no-email") return { subject: "1", username: "ada", email: "", emailVerified: false, groups: ["dev-centr"] }
    return { subject: "1", username: "ada", email: "ada@example.com", emailVerified: true, groups: ["dev-centr"] }
  },
}
const gitlab = { ...forge, id: "gitlab", label: "GitLab (gitlab.com)", host: "gitlab.com", instanceUrl: "https://gitlab.com" }
const client = { id: "preview", secret: "preview", redirectUris: [`${base}/preview/done`] }
const single = createIssuer({ issuer: base, privateKey: pair.privateKey, publicJwk: { ...jwk, kid: "preview" }, kid: "preview", clients: [client], github: forge })
const both = createIssuer({ issuer: base, privateKey: pair.privateKey, publicJwk: { ...jwk, kid: "preview" }, kid: "preview", clients: [client], github: forge, gitlab: [gitlab] })
const authorize = `${base}/authorize?client_id=preview&redirect_uri=${encodeURIComponent(`${base}/preview/done`)}&scope=openid%20email&forge=github`

async function flow(which) {
  mode = which
  const start = await single.handle(new Request(`${authorize}&accepted=1`))
  const state = new URL(start.headers.get("location")).searchParams.get("state")
  return single.handle(new Request(`${base}/github/callback?code=preview&state=${state}`))
}

async function route(request) {
  const url = new URL(request.url)
  if (url.pathname === "/") return Response.redirect(authorize, 302)
  if (url.pathname === "/preview/not-installed") return flow("not-installed")
  if (url.pathname === "/preview/no-email") return flow("no-email")
  if (url.pathname === "/preview/error") return flow("error")
  if (url.pathname === "/preview/bad-redirect") return single.handle(new Request(`${base}/authorize?client_id=preview&redirect_uri=https%3A%2F%2Felsewhere.example%2F&scope=openid`))
  if (url.pathname === "/preview/chooser") return both.handle(new Request(authorize.replace("&forge=github", "")))
  return single.handle(request)
}

createServer(async (req, res) => {
  const response = await route(new Request(`${base}${req.url}`, { method: req.method }))
  const headers = {}
  response.headers.forEach((value, key) => { headers[key] = value })
  res.writeHead(response.status, headers)
  res.end(response.body ? Buffer.from(await response.arrayBuffer()) : undefined)
}).listen(port, "127.0.0.1", () => console.log(`Preview at ${base}/ (Ctrl+C stops it)`))
