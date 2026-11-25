export function bytesToBase64Url(bytes) {
  let bin = ""
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")
}

export function randomId() {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return bytesToBase64Url(bytes)
}

export function pemToBytes(pem) {
  const body = String(pem).replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s+/g, "")
  const bin = atob(body)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i)
  return bytes
}

export async function importSigningKey(pem) {
  return crypto.subtle.importKey(
    "pkcs8",
    pemToBytes(pem),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  )
}

export async function signJwt(privateKey, payload, kid) {
  const header = { alg: "RS256", typ: "JWT", kid }
  const h = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(header)))
  const p = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(payload)))
  const data = new TextEncoder().encode(`${h}.${p}`)
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, privateKey, data))
  return `${h}.${p}.${bytesToBase64Url(sig)}`
}

export async function pkceS256(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))
  return bytesToBase64Url(new Uint8Array(digest))
}

export function secretsMatch(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length || a.length === 0) return false
  let diff = 0
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

export function hostOf(url) {
  return new URL(url).host
}

// Public half of a PKCS#8 RSA key as a JWK, using Web Crypto so Node and Workers agree.
export async function publicJwkFromPem(pem, kid) {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToBytes(pem),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["sign"],
  )
  const full = await crypto.subtle.exportKey("jwk", key)
  return { kty: "RSA", n: full.n, e: full.e, alg: "RS256", use: "sig", kid }
}
