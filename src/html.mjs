import { ASSET_URLS } from "./assets.mjs"

export const CONTRACT_DOC_URL = "https://docs.devcentr.org/tools/private-docs-login/how-to/"
export const SUPPORT_EMAIL = "support@devcentr.org"
export const APP_PAGE_URL = "https://github.com/apps/private-docs-login"

export const ADMIN_MESSAGE = "If you do not want sign-in to pass through the publisher's issuer, stop and give your organization admin this message: this sign-in sends the reader through the publisher's issuer; keeping membership checks on the organization's own host means the organization runs its own issuer and its own GitHub App."

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[c])
}

// Every value interpolated into a page goes through escapeHtml. Page bodies are built from
// these helpers or from literal markup in this file only.
const e = escapeHtml

// Content-Security-Policy for every page. No inline script or style; assets are same-origin.
// form-action also lists the forge origins, because a form GET to /authorize is redirected there.
export function pageCsp(formOrigins = []) {
  const forms = ["'self'", ...formOrigins].join(" ")
  return [
    "default-src 'none'",
    "style-src 'self'",
    "font-src 'self'",
    "img-src 'self'",
    `form-action ${forms}`,
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join("; ")
}

export function page({ title, eyebrow, tone = "ok", lead, body }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex">
<title>${e(title)} · Private Docs Login</title>
<link rel="preload" href="${e(ASSET_URLS.font)}" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="${e(ASSET_URLS.css)}">
<link rel="icon" type="image/svg+xml" href="${e(ASSET_URLS.favicon)}">
</head>
<body class="tone-${tone === "stop" ? "stop" : "ok"}">
<header class="site-header">
<img src="${e(ASSET_URLS.favicon)}" alt="" width="36" height="36">
<span class="brand">Private Docs Login<small>Sign-in for private documentation</small></span>
</header>
<main class="page">
<div class="panel">
<p class="eyebrow">${e(eyebrow)}</p>
<h1>${e(title)}</h1>
${lead ? `<p class="lead">${lead}</p>` : ""}
${body}
</div>
</main>
<footer class="site-footer">
<span>Operated by DevCentr</span>
<a href="${e(CONTRACT_DOC_URL)}">How login works</a>
<a href="mailto:${e(SUPPORT_EMAIL)}">${e(SUPPORT_EMAIL)}</a>
</footer>
</body>
</html>`
}

export function htmlResponse(status, title, body, options = {}) {
  return new Response(page({ title, body, ...options }), {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": pageCsp(),
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
    },
  })
}

function steps(items) {
  return `<ol class="steps">\n${items.map((item) => `<li>${item}</li>`).join("\n")}\n</ol>`
}

function startAgain() {
  return "Go back to the documentation site and sign in again."
}

export function refusalPage({ forge, installUrl, optInUsername, instanceUrl }) {
  if (forge === "gitlab") {
    const name = optInUsername || "the opt-in user"
    return htmlResponse(403, "This group has not opted in", `
<h2>What to do next</h2>
${steps([
  `Ask an owner of your GitLab group to invite the user <strong>${e(name)}</strong> to the group. Guest access is enough.`,
  startAgain(),
])}
<p class="muted">Only groups that invited that user count. A group you belong to that has not invited it is left out, and a personal email address does not grant access.${instanceUrl ? ` The GitLab host for this sign-in is <span class="mono">${e(instanceUrl)}</span>.` : ""}</p>`, {
      eyebrow: "Sign-in stopped",
      tone: "stop",
      lead: "Private Docs Login could not sign you in. You are not a member of a GitLab group that has opted in.",
    })
  }
  return htmlResponse(403, "This organization has not installed the app", `
<h2>What to do next</h2>
${steps([
  "Ask an owner of your GitHub organization to install the app named Private Docs Login.",
  startAgain(),
])}
${installUrl ? `<div class="actions"><a class="button" href="${e(installUrl)}">Install Private Docs Login</a></div>` : ""}
<p class="muted">Membership of an organization that has installed the app is what counts. A personal email address does not grant access.</p>`, {
    eyebrow: "Sign-in stopped",
    tone: "stop",
    lead: "Private Docs Login could not sign you in. Your GitHub user is not a member of an organization that has installed this GitHub App.",
  })
}

export function noVerifiedEmailPage({ forge, instanceUrl }) {
  const fix = forge === "gitlab"
    ? `On GitLab${instanceUrl ? ` (<span class="mono">${e(instanceUrl)}</span>)` : ""}, open User settings, Emails, and confirm your primary address.`
    : `On GitHub, open <a href="https://github.com/settings/emails">Settings, Emails</a> and verify the address marked Primary.`
  return htmlResponse(403, "No verified primary email", `
<h2>What to do next</h2>
${steps([fix, startAgain()])}
<p class="muted">Only the verified primary address is sent to the documentation site. Other addresses on your account are not.</p>`, {
    eyebrow: "Sign-in stopped",
    tone: "stop",
    lead: "Private Docs Login could not sign you in. Your account has no verified primary email address, and the documentation site identifies readers by email.",
  })
}

function hiddenFields(hidden) {
  return Object.entries(hidden)
    .filter(([, v]) => v != null && v !== "")
    .map(([k, v]) => `<input type="hidden" name="${e(k)}" value="${e(v)}">`)
    .join("\n")
}

function contractLink() {
  return `<p class="muted">The full contract is <a href="${e(CONTRACT_DOC_URL)}">How login works and Run your own issuer</a>.</p>`
}

function connectExplanation() {
  return `
<ul class="plain">
<li>This sign-in uses one published GitHub App. Its only GitHub callback is this issuer. Customer documentation URLs are not entered on that app.</li>
<li>A private documentation site admits a reader only if the token names that organization. Installing the app lets this issuer name that organization's members in tokens for private documentation sites registered here. Each site checks for its own organization.</li>
<li>Reader sign-in, the fact of membership, and the return to a registered site pass through the publisher's issuer.</li>
</ul>
<details>
<summary>Before you continue</summary>
<p>${e(ADMIN_MESSAGE)}</p>
</details>
${contractLink()}`
}

const CONNECT_LEAD = "This is a login provider for private documentation sites that use OpenID Connect. It checks your GitHub or GitLab membership and sends you back to the site. An Antora site behind Cloudflare Access, or another OpenID Connect relying party, is one common setup."

export function connectAcceptancePage(hidden) {
  return htmlResponse(200, "Sign in to private documentation", `
${connectExplanation()}
<form class="actions" action="/authorize" method="get">
${hiddenFields(hidden)}
<input type="hidden" name="accepted" value="1">
<button class="button" type="submit">Continue to ${hidden.forge === "gitlab" ? "GitLab" : "GitHub"}</button>
</form>`, {
    eyebrow: "Sign in through the publisher's issuer",
    lead: CONNECT_LEAD,
  })
}

export function chooserPage(providers, hidden) {
  const fields = hiddenFields(hidden)
  const buttons = providers.map((p, index) => {
    const extra = p.instanceUrl
      ? `<input type="hidden" name="instance" value="${e(p.instanceUrl)}">`
      : ""
    return `<form id="${e(p.formId)}" action="/authorize" method="get">
${fields}
<input type="hidden" name="forge" value="${e(p.forge)}">
<input type="hidden" name="accepted" value="1">
${extra}
<button class="button${index === 0 ? "" : " secondary"}" type="submit">${e(p.label)}</button>
</form>`
  }).join("\n")
  return htmlResponse(200, "Choose where to sign in", `
${connectExplanation()}
<p>Choose GitHub or a GitLab host. You will come back here only if that organization or group has not opted in.</p>
<div class="actions">
${buttons}
</div>`, {
    eyebrow: "Sign in through the publisher's issuer",
    lead: CONNECT_LEAD,
  })
}

const SETUP_ACTIONS = {
  install: { eyebrow: "Installed", title: "Private Docs Login is installed" },
  update: { eyebrow: "Installation updated", title: "Private Docs Login is updated" },
  request: { eyebrow: "Install requested", title: "Your install request was sent" },
}

// GitHub sends the reader here after an install with installation_id and setup_action. Both are
// shown only after validation: the id must be digits, the action one of GitHub's three values.
export function installSetupPage({ issuer = "", installationId = "", setupAction = "" } = {}) {
  const id = /^\d{1,20}$/.test(String(installationId)) ? String(installationId) : ""
  const action = SETUP_ACTIONS[setupAction] ? setupAction : "install"
  const copy = SETUP_ACTIONS[action]
  const root = String(issuer).replace(/\/$/, "")
  const summary = `<dl class="settings">
${id ? `<dt>Installation</dt><dd>${e(id)}</dd>` : ""}
<dt>GitHub App</dt><dd>Private Docs Login</dd>
${root ? `<dt>Issuer</dt><dd>${e(root)}</dd>` : ""}
</dl>`
  if (action === "request") {
    return htmlResponse(200, copy.title, `
${summary}
<h2>What happens next</h2>
${steps([
  "An owner of the organization approves the request on GitHub.",
  "After approval, members can sign in to documentation sites that use this issuer and check for that organization.",
])}
${contractLink()}`, {
      eyebrow: copy.eyebrow,
      lead: "A login provider for OpenID Connect-enabled private sites. GitHub asked an organization owner to approve the install.",
    })
  }
  const accessFields = root ? `<dl class="settings">
<dt>Auth URL</dt><dd>${e(root)}/authorize</dd>
<dt>Token URL</dt><dd>${e(root)}/token</dd>
<dt>Certificate URL</dt><dd>${e(root)}/jwks</dd>
<dt>Scopes</dt><dd>openid email</dd>
<dt>Claims</dt><dd>email, groups</dd>
</dl>` : ""
  return htmlResponse(200, copy.title, `
${summary}
<h2>What this installation allows</h2>
<ul class="plain">
<li>Installing this app lets this issuer name members of this organization in tokens for private documentation sites registered with the issuer.</li>
<li>It does not add those members to someone else's documentation. Each site still checks for its own organization.</li>
<li>Reader sign-in, membership checks, and the return to a registered site pass through the publisher's host. To keep them on your own host, run your own issuer and your own GitHub App.</li>
</ul>
<h2>Connect your team docs</h2>
<p>An Antora site behind Cloudflare Access, or another OpenID Connect relying party, is one common setup. For Cloudflare Access:</p>
${steps([
  `Ask the issuer operator at <a href="mailto:${e(SUPPORT_EMAIL)}">${e(SUPPORT_EMAIL)}</a> to register your Access callback, <span class="mono">https://&lt;team&gt;.cloudflareaccess.com/cdn-cgi/access/callback</span>. You get a client id and a client secret back.`,
  "In Cloudflare Zero Trust, add an OpenID Connect login method with these values and that client id and secret.",
  `In the Access application for your docs, allow the OIDC claim <code>groups</code> with the value <code>github:github.com:&lt;your-organization&gt;</code>.`,
])}
${accessFields}
<div class="actions">
<a class="button" href="${e(CONTRACT_DOC_URL)}">Read the setup guide</a>
<a class="button secondary" href="${e(APP_PAGE_URL)}">Manage the app on GitHub</a>
</div>
<p class="muted">A login provider for OpenID Connect-enabled private sites. The full contract is <a href="${e(CONTRACT_DOC_URL)}">How login works and Run your own issuer</a>.</p>`, {
    eyebrow: copy.eyebrow,
    lead: "Members of your organization can now sign in to private documentation sites that use this issuer and check for your organization.",
  })
}

export function badRedirectPage() {
  return htmlResponse(400, "This return address is not registered", `
<h2>What to do next</h2>
${steps([
  "If you followed a link, go back to the documentation site and start sign-in from there.",
  "If you run the documentation site, add the exact redirect URI to the issuer's client registration, then try again.",
])}`, {
    eyebrow: "Sign-in link problem",
    tone: "stop",
    lead: "This sign-in link uses a return address that is not registered for that client, so the issuer will not send you there.",
  })
}

export function forgeErrorPage(forge) {
  return htmlResponse(502, "Sign-in did not finish", `
<h2>What to do next</h2>
${steps([
  startAgain(),
  `If it keeps failing, write to <a href="mailto:${e(SUPPORT_EMAIL)}">${e(SUPPORT_EMAIL)}</a>. The issuer operator checks the app credentials.`,
])}`, {
    eyebrow: "Something went wrong",
    tone: "stop",
    lead: `${e(forge)} did not complete sign-in.`,
  })
}
