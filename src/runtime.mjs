// Runtime config from parsed SDL and an environment object. No filesystem or Node-only import, so the
// Node host and the Cloudflare Worker host build the issuer the same way.
import { asList } from "./sdl.mjs"
import { importSigningKey, publicJwkFromPem } from "./codec.mjs"

export function describeConfig(raw) {
  if (!raw || typeof raw.issuer !== "string" || !raw.issuer) {
    throw new Error("Config needs an issuer URL")
  }
  return {
    issuer: raw.issuer.replace(/\/$/, ""),
    groupsClaim: raw["groups-claim"] || "groups",
  }
}

export function envValue(env, name) {
  // Trimmed, because a secret piped in from a shell often carries a trailing newline.
  const value = typeof env[name] === "string" ? env[name].trim() : env[name]
  if (!value) throw new Error(`Set environment variable ${name}`)
  return value
}

// The signing key is either PEM text in an environment value (pem-env, the Worker secret) or a path
// to a PEM file (pem-path-env, the Node host). readText is only needed for the path form.
export function signingPem(raw, env, readText) {
  const signing = raw["signing-key"] || {}
  const pemEnv = signing["pem-env"]
  const pathEnv = signing["pem-path-env"] || (pemEnv ? "" : "PRIVATE_DOCS_LOGIN_SIGNING_KEY_PATH")
  if (pemEnv && env[pemEnv]) return env[pemEnv]
  if (pathEnv && env[pathEnv]) {
    if (!readText) throw new Error(`${pathEnv} is a file path, and this host cannot read files. Set ${pemEnv || "signing-key.pem-env"} instead.`)
    return readText(env[pathEnv])
  }
  const names = [pemEnv, pathEnv].filter(Boolean).join(" or ")
  throw new Error(`Set environment variable ${names}`)
}

// Public keys still published after a rotation, so tokens signed with the old key verify until they expire.
export function previousJwks(raw, env) {
  const name = (raw["signing-key"] || {})["previous-jwks-env"]
  if (!name || !env[name]) return []
  let parsed
  try {
    parsed = JSON.parse(env[name])
  } catch {
    throw new Error(`${name} is not JSON. It holds the previous public keys as a JWKS or a list of JWKs.`)
  }
  const keys = Array.isArray(parsed) ? parsed : (parsed.keys || [])
  return keys.map((key) => {
    if (key.d || key.p || key.q) throw new Error(`${name} holds private key material. Publish public keys only.`)
    if (key.kty !== "RSA" || !key.n || !key.e || !key.kid) throw new Error(`${name} has a key without kty RSA, n, e, and kid.`)
    return { kty: "RSA", n: key.n, e: key.e, alg: "RS256", use: "sig", kid: key.kid }
  })
}

export function statePath(raw, env) {
  const name = (raw.state || {})["sqlite-path-env"] || "PRIVATE_DOCS_LOGIN_STATE_PATH"
  return env[name] || ""
}

export async function buildRuntime(raw, env, { readText } = {}) {
  const described = describeConfig(raw)
  const listen = raw.listen || {}
  const signing = raw["signing-key"] || {}
  const kid = signing.kid || "private-docs-login-1"
  const pem = signingPem(raw, env, readText)
  const privateKey = await importSigningKey(pem)
  const publicJwk = await publicJwkFromPem(pem, kid)
  const previous = previousJwks(raw, env).filter((key) => key.kid !== kid)
  const clients = asList(raw.client).map((client) => ({
    id: client.id,
    secret: envValue(env, client["secret-env"]),
    redirectUris: asList(client.redirect),
  }))
  let github = null
  if (raw.github) {
    github = {
      webBase: raw.github.web || "https://github.com",
      apiBase: raw.github.api || "https://api.github.com",
      owner: raw.github.owner,
      slug: raw.github.slug || "private-docs-login",
      appId: envValue(env, raw.github["app-id-env"]),
      clientId: envValue(env, raw.github["client-id-env"]),
      clientSecret: envValue(env, raw.github["client-secret-env"]),
    }
  }
  const gitlab = asList(raw.gitlab && raw.gitlab.instance).map((instance) => ({
    instanceUrl: instance.url,
    ownerGroup: instance["owner-group"],
    optInUsername: instance["opt-in-username"],
    clientId: envValue(env, instance["client-id-env"]),
    clientSecret: envValue(env, instance["client-secret-env"]),
  }))
  const listenOverride = env.PRIVATE_DOCS_LOGIN_LISTEN
  let host = listen.host || "127.0.0.1"
  let port = Number(listen.port || 4180)
  if (listenOverride) {
    const split = listenOverride.lastIndexOf(":")
    host = listenOverride.slice(0, split)
    port = Number(listenOverride.slice(split + 1))
  }
  return {
    ...described,
    listenHost: host,
    listenPort: port,
    kid,
    privateKey,
    publicJwk,
    previousPublicJwks: previous,
    statePath: statePath(raw, env),
    clients,
    github,
    gitlab,
  }
}
