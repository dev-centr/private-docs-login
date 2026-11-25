// Request handling for the Cloudflare Worker host. worker.mjs bundles the config text and exports
// createWorker() as the Worker. Kept separate so Node tests can drive it with a fake D1 binding.
import { parseSdl } from "../../src/sdl.mjs"
import { buildRuntime } from "../../src/runtime.mjs"
import { issuerFromRuntime } from "../../src/app.mjs"
import { d1Stores } from "../../src/store.mjs"

export function createWorker({ config }) {
  let ready = null
  let readyFor = null

  function issuerFor(env) {
    // Build once per isolate. Secrets do not change within an isolate, so env is the cache key.
    if (ready && readyFor === env) return ready
    readyFor = env
    ready = (async () => {
      if (!env.PRIVATE_DOCS_LOGIN_STATE) throw new Error("The Worker has no D1 binding named PRIVATE_DOCS_LOGIN_STATE.")
      const runtime = await buildRuntime(parseSdl(config), env)
      return issuerFromRuntime(runtime, { stores: d1Stores(env.PRIVATE_DOCS_LOGIN_STATE) })
    })()
    ready.catch(() => { ready = null; readyFor = null })
    return ready
  }

  return {
    async fetch(request, env) {
      let issuer
      try {
        issuer = await issuerFor(env)
      } catch (error) {
        console.error(error.message)
        const path = new URL(request.url).pathname
        const body = path === "/healthz"
          ? JSON.stringify({ ok: false, state: "not-configured" })
          : "The issuer is not configured. The operator can read the Worker logs."
        return new Response(body, {
          status: 503,
          headers: { "content-type": path === "/healthz" ? "application/json" : "text/plain; charset=utf-8", "cache-control": "no-store" },
        })
      }
      try {
        return await issuer.handle(request)
      } catch (error) {
        console.error(error.message)
        return new Response("The issuer hit an error. The operator can read the Worker logs.", {
          status: 500,
          headers: { "content-type": "text/plain; charset=utf-8" },
        })
      }
    },
  }
}
