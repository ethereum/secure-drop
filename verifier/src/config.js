const path = require("node:path")

const REQUIRED = ["ZKPASSPORT_DOMAIN"]
const FACEMATCH_MODES = ["strict", "regular", "off"]

function loadConfig(env = process.env) {
  const missing = REQUIRED.filter((name) => !env[name])
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`)
  }

  // Everything the verifier writes lives under one directory: the circuit
  // artifacts the SDK downloads, and the 4 MB reference string the native bb
  // binary keeps in .bb-crs. The binary learns that path only from the
  // CRS_PATH environment variable (it defaults to $HOME/.bb-crs), so server.js
  // exports crsPath before anything spawns it.
  const cacheDir = path.resolve(env.CACHE_DIR || "/tmp/zkp")
  const config = {
    port: Number(env.PORT || 3000),
    domain: env.ZKPASSPORT_DOMAIN,
    facematch: env.ZKPASSPORT_FACEMATCH || "strict",
    publicKeysJsPath: path.resolve(env.PUBLIC_KEYS_JS_PATH || "/app/static/js/public-keys.js"),
    cacheDir,
    crsPath: path.join(cacheDir, ".bb-crs"),
    gitSha: env.GIT_SHA || "unknown",
  }

  if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
    throw new Error(`PORT must be a whole number between 1 and 65535, got "${env.PORT}"`)
  }
  if (!FACEMATCH_MODES.includes(config.facematch)) {
    throw new Error(`ZKPASSPORT_FACEMATCH must be one of ${FACEMATCH_MODES.join(", ")}, got "${config.facematch}"`)
  }
  return config
}

module.exports = { loadConfig, FACEMATCH_MODES }
