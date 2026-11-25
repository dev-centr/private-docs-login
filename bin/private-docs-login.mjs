#!/usr/bin/env node
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import { describeConfig, readConfigFile } from "../src/config.mjs"
import { asList } from "../src/sdl.mjs"
import { listenIssuer } from "../src/serve.mjs"
import { manifestPlan, startManifestServer, writeGithubCredentials } from "../src/manifest.mjs"
import { gitlabSetupText } from "../src/gitlab-setup.mjs"

const version = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version

const help = `Private Docs Login is a login provider for private documentation sites.
It is an OpenID Connect issuer. It brokers GitHub and GitLab membership for those sites.
GitHub organizations opt in by installing one GitHub App. GitLab groups opt in by inviting a configured user. The ID token lists those organizations and groups.
Antora is one example client.

This command runs in a checkout of this repository, on a machine that hosts the issuer.
Installing the published GitHub App on an organization does not use this command.

Start the issuer in this window:
  private-docs-login serve --config config/issuer.sdl
  This window shows the process. The listen line is the address. Ctrl+C stops it.

Create the GitHub App (one approval in the browser):
  private-docs-login github-manifest --config config/issuer.sdl
  The DevCentr-hosted issuer uses --config deploy/cloudflare/issuer.sdl (owner dev-centr).

Print the GitLab application steps:
  private-docs-login gitlab-setup --config config/issuer.sdl

--version prints ${version}. Environment names are listed in docs/modules/private-docs-login/pages/environment-variables.adoc.
`

function flag(args, name, fallback) {
  const index = args.indexOf(name)
  if (index === -1) return fallback
  return args[index + 1]
}

const args = process.argv.slice(2)
if (args.includes("--help") || args.includes("-h") || args.length === 0) {
  console.log(help)
  process.exit(0)
}
if (args.includes("--version") || args.includes("-v")) {
  console.log(version)
  process.exit(0)
}

const command = args[0]
const configPath = flag(args, "--config", process.env.PRIVATE_DOCS_LOGIN_CONFIG || "config/issuer.sdl")

if (command === "serve") {
  const started = await listenIssuer({ configPath, env: process.env })
  const address = started.server.address()
  console.log(`This window is showing Private Docs Login.`)
  console.log(`Listen ${started.runtime.listenHost}:${address.port}`)
  console.log(`Issuer ${started.runtime.issuer}`)
  console.log(`Groups claim ${started.runtime.groupsClaim}`)
  console.log(started.storage === "sqlite"
    ? `State SQLite ${started.runtime.statePath}`
    : "State in memory. A restart drops sign-ins in progress. Set PRIVATE_DOCS_LOGIN_STATE_PATH to keep them.")
  console.log(`Ctrl+C stops this process.`)
} else if (command === "github-manifest") {
  const raw = readConfigFile(configPath)
  const described = describeConfig(raw)
  const github = raw.github || {}
  const host = flag(args, "--listen-host", "127.0.0.1")
  const port = Number(flag(args, "--listen-port", "8765"))
  let plan
  try {
    plan = manifestPlan({ webBase: github.web, owner: github.owner, issuer: described.issuer, setupOrigin: `http://${host}:${port}` })
  } catch (error) {
    console.error(error.message)
    process.exit(1)
  }
  console.log(`Owner ${plan.owner}`)
  console.log(`GitHub form ${plan.action}`)
  console.log(`Callback URL ${plan.callbackUrl}`)
  console.log(`Setup URL ${plan.setupUrl}`)
  console.log(`Manifest return ${plan.redirectUrl}`)
  const server = await startManifestServer({
    host,
    port,
    webBase: github.web || "https://github.com",
    owner: github.owner,
    issuer: described.issuer,
    fetchImpl: globalThis.fetch,
    onCredentials(body) {
      const written = writeGithubCredentials(join(dirname(fileURLToPath(import.meta.url)), "..", "var"), body)
      console.log(`GitHub App id ${written.id}. Slug ${written.slug || "(not returned)"}.`)
      console.log(`Wrote ${written.jsonPath}`)
      console.log(`Wrote ${written.pemPath}`)
      console.log("Set the GitHub env names in docs/modules/private-docs-login/pages/environment-variables.adoc from that file. This command does not print the client secret or the private key.")
    },
  })
  console.log(`This window is showing the GitHub App setup.`)
  console.log(`Open http://${host}:${port}/`)
  console.log("The form posts the manifest to GitHub. Approve Private Docs Login there. Ctrl+C stops this process.")
  void server
} else if (command === "gitlab-setup") {
  const raw = readConfigFile(configPath)
  const described = describeConfig(raw)
  const instances = asList(raw.gitlab && raw.gitlab.instance)
  if (instances.length === 0) {
    console.error("The config has no GitLab instance.")
    process.exit(1)
  }
  for (const instance of instances) {
    const text = await gitlabSetupText({
      instance: {
        instanceUrl: instance.url,
        ownerGroup: instance["owner-group"],
        optInUsername: instance["opt-in-username"],
      },
      issuer: described.issuer,
      fetchImpl: globalThis.fetch,
    })
    console.log(text)
    console.log("")
  }
} else {
  console.error(help)
  process.exit(1)
}
