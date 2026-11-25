// Cloudflare Worker host for Private Docs Login. Optional: the Node server in src/serve.mjs stays the
// reference host, and nothing in src/ imports this file or a Workers-only module.
import config from "./issuer.sdl"
import { createWorker } from "./worker-core.mjs"

export default createWorker({ config })
