import { hostOf, parseBasicClient, pkceS256, randomId, secretsEqual, signJwt } from "./codec.mjs"
import { badRedirectPage, chooserPage, connectAcceptancePage, forgeErrorPage, installSetupPage, noVerifiedEmailPage, refusalPage } from "./html.mjs"
import { memoryStore } from "./store.mjs"

const REQUEST_TTL = 10 * 60 * 1000
const CODE_TTL = 5 * 60 * 1000
const TOKEN_TTL = 10 * 60

export function createIssuer(options) {
  const now = options.now || (() => Date.now())
  const stores = options.stores || {}
  const requests = options.requests || stores.requests || memoryStore(now)
  const codes = options.codes || stores.codes || memoryStore(now)
  const accessTokens = options.accessTokens || stores.accessTokens || memoryStore(now)
  const storageLabel = stores.label || "memory"
  const signingKeys = [options.publicJwk, ...(options.previousPublicJwks || [])].filter(Boolean)
  const issuer = options.issuer.replace(/\/$/, "")
  const groupsClaim = options.groupsClaim || "groups"
  const providers = [
    ...(options.github ? [options.github] : []),
    ...((options.gitlab || [])),
  ]

  async function handle(request) {
    const url = new URL(request.url)
    if (request.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
      return json(discovery(issuer, groupsClaim))
    }
    if (request.method === "GET" && url.pathname === "/jwks") return jwks(signingKeys)
    if (request.method === "GET" && url.pathname === "/github/setup") return installSetupPage()
    if (request.method === "GET" && url.pathname === "/authorize") return authorize(url)
    if (request.method === "GET" && (url.pathname === "/github/callback" || url.pathname === "/gitlab/callback")) {
      return callback(url)
    }
    if (request.method === "POST" && url.pathname === "/token") return token(request)
    if (request.method === "GET" && url.pathname === "/userinfo") return userinfo(request)
    if (request.method === "GET" && url.pathname === "/health") return json({ ok: true })
    if (request.method === "GET" && url.pathname === "/healthz") return healthz()
    return json({ error: "not_found" }, 404)
  }

  async function authorize(url) {
    const params = url.searchParams
    const client = findClient(options.clients, params.get("client_id"))
    if (!client) return json({ error: "unauthorized_client" }, 400)
    const redirectUri = params.get("redirect_uri") || ""
    if (!client.redirectUris.includes(redirectUri)) return badRedirectPage()
    if ((params.get("response_type") || "code") !== "code") return json({ error: "unsupported_response_type" }, 400)
    const scope = params.get("scope") || "openid"
    if (!scope.split(" ").includes("openid")) return json({ error: "invalid_scope" }, 400)
    const forgeId = params.get("forge")
    const instance = params.get("instance")
    const matches = providers.filter((provider) => {
      if (forgeId && provider.id !== forgeId) return false
      if (provider.id === "gitlab" && instance && provider.instanceUrl !== instance.replace(/\/$/, "")) return false
      return true
    })
    if (matches.length === 0) return json({ error: "invalid_request", error_description: "unknown forge" }, 400)
    const pendingFields = {
      client_id: client.id,
      redirect_uri: redirectUri,
      response_type: "code",
      scope,
      state: params.get("state") || "",
      nonce: params.get("nonce") || "",
      code_challenge: params.get("code_challenge") || "",
      code_challenge_method: params.get("code_challenge_method") || "",
    }
    if (matches.length > 1) {
      return chooserPage(matches.map((provider, index) => ({
        forge: provider.id,
        label: provider.label,
        instanceUrl: provider.instanceUrl || "",
        formId: `forge-${index}`,
      })), pendingFields)
    }
    const provider = matches[0]
    if (params.get("accepted") !== "1") {
      return connectAcceptancePage({
        ...pendingFields,
        forge: provider.id,
        instance: provider.instanceUrl || "",
      })
    }
    const state = randomId()
    await requests.put(state, {
      clientId: client.id,
      redirectUri,
      clientState: params.get("state") || "",
      nonce: params.get("nonce") || "",
      codeChallenge: params.get("code_challenge") || "",
      codeChallengeMethod: params.get("code_challenge_method") || "",
      providerId: provider.id,
      instanceUrl: provider.instanceUrl || "",
    }, REQUEST_TTL)
    const location = await provider.authorizationUrl({
      redirectUri: `${issuer}${provider.id === "github" ? "/github/callback" : "/gitlab/callback"}`,
      state,
    })
    return redirect(location)
  }

  async function callback(url) {
    const state = url.searchParams.get("state") || ""
    const pending = await requests.take(state)
    if (!pending) return json({ error: "invalid_request", error_description: "unknown or expired sign-in" }, 400)
    const provider = providers.find((item) => item.id === pending.providerId && (item.instanceUrl || "") === pending.instanceUrl)
    if (!provider) return json({ error: "invalid_request" }, 400)
    const code = url.searchParams.get("code")
    if (!code) return forgeErrorPage(provider.label)
    let login
    try {
      login = await provider.complete({
        code,
        redirectUri: `${issuer}${provider.id === "github" ? "/github/callback" : "/gitlab/callback"}`,
      })
    } catch {
      return forgeErrorPage(provider.label)
    }
    const names = login.groups || []
    if (names.length === 0) {
      return refusalPage({
        forge: provider.id,
        installUrl: provider.installUrl,
        optInUsername: provider.optInUsername,
        instanceUrl: provider.instanceUrl,
      })
    }
    // Cloudflare Access names readers by email, so a sign-in without a verified primary address stops here.
    if (!login.email || login.emailVerified !== true) {
      return noVerifiedEmailPage({ forge: provider.id, instanceUrl: provider.instanceUrl })
    }
    const prefix = provider.id === "github" ? "github" : "gitlab"
    const groups = names.map((name) => `${prefix}:${provider.host}:${name}`)
    const authCode = randomId()
    await codes.put(authCode, {
      ...pending,
      subject: `${prefix}:${provider.host}:${login.subject}`,
      username: login.username,
      email: login.email,
      groups,
      forge: provider.id,
    }, CODE_TTL)
    const dest = new URL(pending.redirectUri)
    dest.searchParams.set("code", authCode)
    if (pending.clientState) dest.searchParams.set("state", pending.clientState)
    return redirect(dest.toString())
  }

  async function token(request) {
    const form = new URLSearchParams(await request.text())
    if (form.get("grant_type") !== "authorization_code") return json({ error: "unsupported_grant_type" }, 400)
    const auth = await authenticateClient(request, form)
    if (auth.response) return auth.response
    const client = auth.client
    const record = await codes.take(form.get("code") || "")
    if (!record || record.clientId !== client.id) return json({ error: "invalid_grant" }, 400)
    if (form.get("redirect_uri") !== record.redirectUri) return json({ error: "invalid_grant" }, 400)
    if (record.codeChallenge) {
      const verifier = form.get("code_verifier") || ""
      const method = record.codeChallengeMethod || "S256"
      if (method !== "S256") return json({ error: "invalid_request" }, 400)
      if (await pkceS256(verifier) !== record.codeChallenge) return json({ error: "invalid_grant" }, 400)
    }
    const issued = now()
    const payload = {
      iss: issuer,
      sub: record.subject,
      aud: client.id,
      iat: Math.floor(issued / 1000),
      exp: Math.floor(issued / 1000) + TOKEN_TTL,
      preferred_username: record.username,
      email: record.email,
      email_verified: true,
      [groupsClaim]: record.groups,
      forge: record.forge,
    }
    if (record.nonce) payload.nonce = record.nonce
    const idToken = await signJwt(options.privateKey, payload, options.kid)
    const accessToken = randomId()
    await accessTokens.put(accessToken, payload, TOKEN_TTL * 1000)
    return json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: TOKEN_TTL,
      id_token: idToken,
    })
  }

  // client_secret_basic or client_secret_post, never both in one request (RFC 6749 section 2.3).
  async function authenticateClient(request, form) {
    const basic = parseBasicClient(request.headers.get("authorization"))
    const challenge = { "www-authenticate": 'Basic realm="private-docs-login", charset="UTF-8"' }
    if (basic) {
      if (form.has("client_secret")) {
        return { response: json({ error: "invalid_request", error_description: "use one client authentication method" }, 400) }
      }
      if (basic.error) return { response: json({ error: "invalid_client" }, 401, challenge) }
      if (form.has("client_id") && form.get("client_id") !== basic.id) {
        return { response: json({ error: "invalid_request", error_description: "client_id does not match the Authorization header" }, 400) }
      }
      const client = findClient(options.clients, basic.id)
      const ok = await secretsEqual(client ? client.secret : "", basic.secret)
      if (!client || !ok) return { response: json({ error: "invalid_client" }, 401, challenge) }
      return { client }
    }
    const client = findClient(options.clients, form.get("client_id"))
    const ok = await secretsEqual(client ? client.secret : "", form.get("client_secret") || "")
    if (!client || !ok) return { response: json({ error: "invalid_client" }, 401) }
    return { client }
  }

  async function userinfo(request) {
    const header = request.headers.get("authorization") || ""
    const token = header.toLowerCase().startsWith("bearer ") ? header.slice(7) : ""
    const payload = token ? await accessTokens.peek(token) : null
    if (!payload) return json({ error: "invalid_token" }, 401)
    return json({
      sub: payload.sub,
      preferred_username: payload.preferred_username,
      email: payload.email,
      email_verified: payload.email_verified,
      [groupsClaim]: payload[groupsClaim],
      forge: payload.forge,
    })
  }

  async function healthz() {
    // Liveness plus a storage round trip. Names no secret, key material, or client.
    let storage = "ok"
    try {
      await Promise.all([requests.ping(), codes.ping(), accessTokens.ping()])
    } catch {
      storage = "error"
    }
    const ok = storage === "ok" && signingKeys.length > 0
    return json({ ok, issuer, storage: storageLabel, state: storage, kid: options.kid || "" }, ok ? 200 : 503)
  }

  return { handle }
}

function jwks(keys) {
  return new Response(JSON.stringify({ keys }), {
    status: 200,
    headers: { "content-type": "application/json", "cache-control": "public, max-age=300" },
  })
}

function findClient(clients, id) {
  return (clients || []).find((client) => client.id === id) || null
}

function discovery(issuer, groupsClaim) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/jwks`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "email", "profile"],
    claims_supported: ["sub", "iss", "aud", "exp", "iat", "nonce", "preferred_username", "email", "email_verified", groupsClaim, "forge"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
  }
}

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...extraHeaders },
  })
}

function redirect(location) {
  return new Response(null, { status: 302, headers: { location, "cache-control": "no-store" } })
}

export function groupPrefix(forge, host, name) {
  return `${forge}:${host}:${name}`
}

export { hostOf }
