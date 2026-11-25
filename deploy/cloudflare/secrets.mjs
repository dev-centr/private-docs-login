#!/usr/bin/env node
// Builds var/worker-secrets.json for `wrangler secret bulk`, from files in the gitignored var/ folder.
// Prints secret names only, never values. `--clean` deletes the JSON after the upload.
//   var/github-app.json                 written by `private-docs-login github-manifest`
//   var/signing.pem                     issuer signing key; created here when missing
//   var/cloudflare-access-client-secret client secret shared with the Access identity provider; created when missing
import { generateKeyPairSync, randomBytes } from "node:crypto"
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

export function buildWorkerSecrets(varDir, { create = true } = {}) {
  mkdirSync(varDir, { recursive: true })
  const created = []
  const appPath = join(varDir, "github-app.json")
  if (!existsSync(appPath)) {
    throw new Error("var/github-app.json is missing. Run private-docs-login github-manifest --config deploy/cloudflare/issuer.sdl first.")
  }
  const app = JSON.parse(readFileSync(appPath, "utf8"))
  for (const field of ["id", "client_id", "client_secret"]) {
    if (!app[field]) throw new Error(`var/github-app.json has no ${field}.`)
  }
  const pemPath = join(varDir, "signing.pem")
  if (!existsSync(pemPath)) {
    if (!create) throw new Error("var/signing.pem is missing.")
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
    writeFileSync(pemPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 })
    created.push("var/signing.pem")
  }
  const accessPath = join(varDir, "cloudflare-access-client-secret")
  if (!existsSync(accessPath)) {
    if (!create) throw new Error("var/cloudflare-access-client-secret is missing.")
    writeFileSync(accessPath, randomBytes(32).toString("base64url"), { mode: 0o600 })
    created.push("var/cloudflare-access-client-secret")
  }
  const secrets = {
    PRIVATE_DOCS_LOGIN_SIGNING_KEY: readFileSync(pemPath, "utf8"),
    PRIVATE_DOCS_LOGIN_GITHUB_APP_ID: String(app.id),
    PRIVATE_DOCS_LOGIN_GITHUB_CLIENT_ID: String(app.client_id),
    PRIVATE_DOCS_LOGIN_GITHUB_CLIENT_SECRET: String(app.client_secret),
    PRIVATE_DOCS_LOGIN_CLIENT_CLOUDFLARE_ACCESS: readFileSync(accessPath, "utf8").trim(),
  }
  const outPath = join(varDir, "worker-secrets.json")
  writeFileSync(outPath, JSON.stringify(secrets, null, 2), { mode: 0o600 })
  return { outPath, names: Object.keys(secrets), created }
}

const isMain = Boolean(process.argv[1]) && resolve(fileURLToPath(import.meta.url)).toLowerCase() === resolve(process.argv[1]).toLowerCase()
if (isMain) {
  const varDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "var")
  if (process.argv.includes("--clean")) {
    rmSync(join(varDir, "worker-secrets.json"), { force: true })
    console.log("Deleted var/worker-secrets.json.")
  } else {
    try {
      const built = buildWorkerSecrets(varDir)
      for (const file of built.created) console.log(`Created ${file}. Save it in Bitwarden before you delete anything.`)
      console.log(`Wrote var/worker-secrets.json with ${built.names.join(", ")}.`)
      console.log("No values were printed.")
    } catch (error) {
      console.error(error.message)
      process.exit(1)
    }
  }
}
