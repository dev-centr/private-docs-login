export const CONTRACT_DOC_URL = "https://docs.devcentr.org/tools/private-docs-login/how-to/"

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

function page(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
</head>
<body>
<main>
<h1>${escapeHtml(title)}</h1>
${body}
</main>
</body>
</html>`
}

export function htmlResponse(status, title, body) {
  return new Response(page(title, body), {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  })
}

export function refusalPage({ forge, installUrl, optInUsername, instanceUrl }) {
  if (forge === "gitlab") {
    const name = optInUsername || "the opt-in user"
    return htmlResponse(403, "This group has not opted in", `
<p>Private Docs Login could not sign you in. You are not a member of a GitLab group that has opted in.</p>
<p>A group owner opts in by inviting the GitLab user <strong>${escapeHtml(name)}</strong> to the group. Guest access is enough. A group you belong to that has not invited that user is not included. A personal email address does not grant access.</p>
<p>After the invite, sign in again from the documentation site.${instanceUrl ? ` The GitLab host for this login is ${escapeHtml(instanceUrl)}.` : ""}</p>`)
  }
  const link = installUrl
    ? `<p><a href="${escapeHtml(installUrl)}">Install Private Docs Login</a></p>`
    : ""
  return htmlResponse(403, "This organization has not installed the app", `
<p>Private Docs Login could not sign you in. Your GitHub user is not a member of an organization that has installed this GitHub App.</p>
<p>An owner of the organization installs the app named Private Docs Login. After that install, sign in again. A personal email address does not grant access.</p>
${link}`)
}

export function noVerifiedEmailPage({ forge, instanceUrl }) {
  const where = forge === "gitlab"
    ? `GitLab${instanceUrl ? ` (${escapeHtml(instanceUrl)})` : ""}: User settings, Emails. Confirm the primary address.`
    : "GitHub: Settings, Emails. Verify the address marked Primary."
  return htmlResponse(403, "No verified primary email", `
<p>Private Docs Login could not sign you in. Your account has no verified primary email address, and the documentation site identifies readers by email.</p>
<p>Fix it in ${where} Then sign in again from the documentation site.</p>
<p>Only the verified primary address is sent. Other addresses on the account are not.</p>`)
}

function hiddenFields(hidden) {
  return Object.entries(hidden)
    .filter(([, v]) => v != null && v !== "")
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
    .join("\n")
}

function contractLink() {
  return `<p>The full contract is <a href="${escapeHtml(CONTRACT_DOC_URL)}">How login works and Run your own issuer</a>.</p>`
}

function connectExplanation() {
  return `
<p>This is a login provider for private documentation sites that use OpenID Connect. It brokers GitHub and GitLab membership. Member-gated docs hubs, handbooks, and internal guides are the audience. An Antora site behind Cloudflare Access, or another OpenID Connect relying party, is one common setup.</p>
<p>This sign-in uses one published GitHub App. Its only GitHub callback is this issuer. Customer documentation URLs are not entered on that app.</p>
<p>A private documentation site admits a reader only if the token names that organization. Installing the app lets this issuer name that organization's members in tokens for private documentation sites registered here. Each site checks for its own organization.</p>
<p>Reader sign-in, the fact of membership, and the return to a registered site pass through the publisher's issuer.</p>
<p>${escapeHtml(ADMIN_MESSAGE)}</p>
${contractLink()}`
}

export function installSetupPage() {
  return htmlResponse(200, "Private Docs Login is installed", `
<p>A login provider for OpenID Connect-enabled private sites. It lets GitHub and GitLab organization members sign in to private resources when their org has installed the app.</p>
<p>You installed one published GitHub App. Its only GitHub callback is this issuer. Customer documentation URLs are not entered on the GitHub App.</p>
<p>Installing this app lets this issuer name members of this organization in tokens for private documentation sites registered with the issuer. It does not add those members to someone else's documentation. Each site still checks for its own organization.</p>
<p>Member-gated docs hubs, handbooks, and internal guides are the audience. An Antora site behind Cloudflare Access, or another OpenID Connect relying party, is one common setup.</p>
<p>Reader sign-in, membership checks, and the return to a registered site pass through the publisher's host. If you do not want that, do not rely on this installation. Run your own issuer and your own GitHub App. You cannot point this app at an issuer you host.</p>
${contractLink()}`)
}

export function connectAcceptancePage(hidden) {
  return htmlResponse(200, "Sign in through the publisher's issuer", `
${connectExplanation()}
<form action="/authorize" method="get">
${hiddenFields(hidden)}
<input type="hidden" name="accepted" value="1">
<button type="submit">Continue</button>
</form>`)
}

export function chooserPage(providers, hidden) {
  const fields = hiddenFields(hidden)
  const buttons = providers.map((p) => {
    const extra = p.instanceUrl
      ? `<input type="hidden" name="instance" value="${escapeHtml(p.instanceUrl)}" form="${escapeHtml(p.formId)}">`
      : ""
    return `<form id="${escapeHtml(p.formId)}" action="/authorize" method="get">
${fields}
<input type="hidden" name="forge" value="${escapeHtml(p.forge)}">
<input type="hidden" name="accepted" value="1">
${extra}
<button type="submit">${escapeHtml(p.label)}</button>
</form>`
  }).join("\n")
  return htmlResponse(200, "Choose where to sign in", `
${connectExplanation()}
<p>Choose GitHub or a GitLab host. You will come back here only if that organization or group has not opted in.</p>
${buttons}`)
}

export function badRedirectPage() {
  return htmlResponse(400, "This return address is not registered", `
<p>This sign-in link uses a return address that is not registered for that client.</p>
<p>The relying party operator adds the exact redirect URI to the issuer config, then tries the link again.</p>`)
}

export function forgeErrorPage(forge) {
  return htmlResponse(502, "Sign-in did not finish", `
<p>${escapeHtml(forge)} did not complete sign-in.</p>
<p>Start again from the documentation site. If it keeps failing, the issuer operator checks the app credentials.</p>`)
}
