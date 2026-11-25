// Builds the issuer from a runtime config. Shared by the Node host (src/serve.mjs) and the
// Cloudflare Worker host (deploy/cloudflare/worker.mjs); each host passes its own state stores.
import { createGithubForge } from "./github.mjs"
import { createGitlabForge } from "./gitlab.mjs"
import { createIssuer } from "./issuer.mjs"

export function issuerFromRuntime(runtime, { fetchImpl, stores, now } = {}) {
  const fetcher = fetchImpl || ((...args) => globalThis.fetch(...args))
  const github = runtime.github ? createGithubForge({ ...runtime.github, fetchImpl: fetcher }) : null
  const gitlab = runtime.gitlab.map((instance) => createGitlabForge({ ...instance, fetchImpl: fetcher }))
  return createIssuer({
    issuer: runtime.issuer,
    groupsClaim: runtime.groupsClaim,
    clients: runtime.clients,
    privateKey: runtime.privateKey,
    publicJwk: runtime.publicJwk,
    previousPublicJwks: runtime.previousPublicJwks,
    kid: runtime.kid,
    github,
    gitlab,
    stores,
    now,
  })
}
