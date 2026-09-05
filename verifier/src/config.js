const REQUIRED = ["ZKPASSPORT_DOMAIN", "ZKPASSPORT_SCOPE", "ETH_RPC_URL"]
const FACEMATCH_MODES = ["strict", "regular", "off"]

function loadConfig(env = process.env) {
  const missing = REQUIRED.filter((name) => !env[name])
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`)
  }

  const config = {
    port: Number(env.PORT || 3000),
    domain: env.ZKPASSPORT_DOMAIN,
    scope: env.ZKPASSPORT_SCOPE,
    facematch: env.ZKPASSPORT_FACEMATCH || "strict",
    ethRpcUrl: env.ETH_RPC_URL,
    publicKeysJsPath: env.PUBLIC_KEYS_JS_PATH || "/app/static/js/public-keys.js",
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
