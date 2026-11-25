import { createServer } from "node:http"
import { issuerFromRuntime } from "./app.mjs"
import { loadRuntimeConfig, readConfigFile } from "./config.mjs"
import { memoryStores, sqliteStores } from "./store.mjs"

export async function listenIssuer({ configPath, env, fetchImpl }) {
  const raw = readConfigFile(configPath)
  const runtime = await loadRuntimeConfig(raw, env)
  return listenRuntime(runtime, fetchImpl || globalThis.fetch)
}

// State lives in SQLite when PRIVATE_DOCS_LOGIN_STATE_PATH (or state.sqlite-path-env) names a file.
// Without it, state is in memory and a restart drops sign-ins that are in progress.
export async function stateForRuntime(runtime) {
  if (runtime.statePath) return sqliteStores(runtime.statePath)
  return memoryStores()
}

export async function listenRuntime(runtime, fetchImpl, stores) {
  const state = stores || await stateForRuntime(runtime)
  const issuer = issuerFromRuntime(runtime, { fetchImpl, stores: state })
  const server = createServer(async (req, res) => {
    try {
      const host = req.headers.host || `${runtime.listenHost}:${runtime.listenPort}`
      const body = await readBody(req)
      const request = new Request(`http://${host}${req.url}`, {
        method: req.method,
        headers: req.headers,
        body: req.method === "GET" || req.method === "HEAD" ? undefined : body,
      })
      const response = await issuer.handle(request)
      const headers = {}
      response.headers.forEach((value, key) => { headers[key] = value })
      res.writeHead(response.status, headers)
      res.end(Buffer.from(await response.arrayBuffer()))
    } catch (error) {
      res.writeHead(500, { "content-type": "text/plain; charset=utf-8" })
      res.end("The issuer hit an error. The operator can read the process output.")
      console.error(error.message)
    }
  })
  server.on("close", () => { if (state.close) state.close() })
  await new Promise((resolve) => server.listen(runtime.listenPort, runtime.listenHost, resolve))
  return { server, runtime, storage: state.label }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    req.on("data", (chunk) => chunks.push(chunk))
    req.on("end", () => resolve(Buffer.concat(chunks)))
    req.on("error", reject)
  })
}
