import { createServer } from "node:http"
import { mkdirSync, writeFileSync } from "node:fs"
import { githubManifest } from "./github.mjs"
import { escapeHtml, page } from "./html.mjs"
import { assetResponse } from "./assets.mjs"

// Checks the config before anything is sent to GitHub, and returns the URLs the app will be created with.
export function manifestPlan({ webBase, owner, issuer, setupOrigin }) {
  if (!owner || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner)) {
    throw new Error("Set github.owner in the config to the organization that will own the app, for example dev-centr.")
  }
  const root = String(issuer || "").replace(/\/$/, "")
  const parsed = new URL(root)
  const local = parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost"
  if (parsed.protocol !== "https:" && !local) {
    throw new Error(`The issuer ${root} is not https. GitHub would send members to a plain-http callback.`)
  }
  const manifest = githubManifest({ issuer: root, setupOrigin })
  return {
    owner,
    action: manifestAction(webBase, owner),
    manifest,
    callbackUrl: manifest.callback_urls[0],
    setupUrl: manifest.setup_url,
    redirectUrl: manifest.redirect_url,
  }
}

export function manifestAction(webBase, owner) {
  return `${(webBase || "https://github.com").replace(/\/$/, "")}/organizations/${encodeURIComponent(owner)}/settings/apps/new`
}

export function manifestForm({ webBase, owner, manifest }) {
  const action = manifestAction(webBase, owner)
  // The manifest travels as an escaped attribute value, so the page needs no script.
  return page({
    title: "Create the GitHub App",
    eyebrow: "Operator setup",
    lead: `Private Docs Login is one GitHub App. This page sends GitHub the manifest, and you approve it on the next screen. The app is owned by ${escapeHtml(owner)}.`,
    body: `<p>GitHub's install dialog shows this description, and nothing else from this repository: ${escapeHtml(manifest.description || "")}</p>
<p class="muted">Leave this window open. GitHub will return here with a code, and the command will write credentials into a gitignored folder.</p>
<form class="actions" method="post" action="${escapeHtml(action)}">
<input type="hidden" name="manifest" value="${escapeHtml(JSON.stringify(manifest))}">
<button class="button" type="submit">Continue to GitHub</button>
</form>`,
  })
}

export function startManifestServer({ host, port, webBase, owner, issuer, fetchImpl, onCredentials }) {
  const origin = `http://${host}:${port}`
  const { manifest } = manifestPlan({ webBase, owner, issuer, setupOrigin: origin })
  const server = createServer(async (req, res) => {
    const url = new URL(req.url || "/", origin)
    const asset = req.method === "GET" ? assetResponse(url.pathname) : null
    if (asset) {
      const headers = {}
      asset.headers.forEach((value, key) => { headers[key] = value })
      res.writeHead(asset.status, headers)
      res.end(asset.body ? Buffer.from(await asset.arrayBuffer()) : undefined)
      return
    }
    if (req.method === "GET" && url.pathname === "/") {
      const html = manifestForm({ webBase, owner, manifest })
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" })
      res.end(html)
      return
    }
    if (req.method === "GET" && url.pathname === "/setup/github/callback") {
      const code = url.searchParams.get("code")
      if (!code) {
        res.writeHead(400, { "content-type": "text/plain; charset=utf-8" })
        res.end("GitHub did not return a code. Run github-manifest again.")
        return
      }
      try {
        const exchanged = await exchangeManifestCode(fetchImpl, code)
        onCredentials(exchanged)
        res.writeHead(200, { "content-type": "text/plain; charset=utf-8" })
        res.end("GitHub App created. Credentials were written to the gitignored var folder. You can close this window.")
      } catch (error) {
        res.writeHead(502, { "content-type": "text/plain; charset=utf-8" })
        res.end(`GitHub did not exchange the manifest code. ${error.message}`)
      }
      return
    }
    res.writeHead(404)
    res.end()
  })
  return new Promise((resolve) => {
    server.listen(port, host, () => resolve(server))
  })
}

export async function exchangeManifestCode(fetchImpl, code) {
  const res = await fetchImpl(`https://api.github.com/app-manifests/${encodeURIComponent(code)}/conversions`, {
    method: "POST",
    headers: {
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "private-docs-login",
    },
  })
  if (!res.ok) throw new Error(`GitHub manifest exchange responded ${res.status}`)
  const body = await res.json()
  if (body.name !== "Private Docs Login") {
    throw new Error("GitHub returned an app whose name is not Private Docs Login")
  }
  return body
}

export function writeGithubCredentials(dir, body) {
  mkdirSync(dir, { recursive: true })
  const pemPath = `${dir}/github-app.pem`
  writeFileSync(pemPath, body.pem || "", { mode: 0o600 })
  writeFileSync(`${dir}/github-app.json`, JSON.stringify({
    id: body.id,
    client_id: body.client_id,
    client_secret: body.client_secret,
    html_url: body.html_url,
    slug: body.slug,
    pem_path: pemPath,
  }, null, 2), { mode: 0o600 })
  return { id: body.id, slug: body.slug, pemPath, jsonPath: `${dir}/github-app.json` }
}
