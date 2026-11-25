import { readFileSync } from "node:fs"
import { parseSdl } from "./sdl.mjs"
import { buildRuntime, describeConfig } from "./runtime.mjs"

export { describeConfig }

export function readConfigFile(path) {
  return parseSdl(readFileSync(path, "utf8"))
}

// Node host: the signing key may be a file path as well as PEM text in the environment.
export async function loadRuntimeConfig(raw, env) {
  return buildRuntime(raw, env, { readText: (path) => readFileSync(path, "utf8") })
}
