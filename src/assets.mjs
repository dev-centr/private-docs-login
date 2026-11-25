// Serves the bundled page assets (stylesheet, font, logo) from memory. Paths carry a content hash,
// so responses are cacheable for a year.
import { ASSET_FILES, ASSET_URLS } from "./assets.generated.mjs"

export { ASSET_URLS }

const decoded = new Map()

function bytesOf(path) {
  if (!decoded.has(path)) {
    const bin = atob(ASSET_FILES[path].base64)
    decoded.set(path, Uint8Array.from(bin, (c) => c.charCodeAt(0)))
  }
  return decoded.get(path)
}

export function assetResponse(pathname, method = "GET") {
  if (pathname === "/favicon.ico" || pathname === "/favicon.svg") {
    return new Response(null, { status: 301, headers: { location: ASSET_URLS.favicon, "cache-control": "public, max-age=86400" } })
  }
  const file = ASSET_FILES[pathname]
  if (!file) return null
  const body = method === "HEAD" ? null : bytesOf(pathname)
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": file.type,
      "cache-control": "public, max-age=31536000, immutable",
      "x-content-type-options": "nosniff",
      "access-control-allow-origin": "*",
    },
  })
}
