const { test } = require("node:test")
const assert = require("node:assert/strict")
const { loadConfig } = require("../src/config")

const minimal = {
  ZKPASSPORT_DOMAIN: "localhost",
  ZKPASSPORT_SCOPE: "ef-onboarding",
  ETH_RPC_URL: "http://rpc.internal:8545",
}

test("loads with defaults", () => {
  assert.deepEqual(loadConfig(minimal), {
    port: 3000,
    domain: "localhost",
    scope: "ef-onboarding",
    facematch: "strict",
    ethRpcUrl: "http://rpc.internal:8545",
    publicKeysJsPath: "/app/static/js/public-keys.js",
  })
})

test("reports every missing variable at once", () => {
  assert.throws(() => loadConfig({ ZKPASSPORT_SCOPE: "x" }), /ZKPASSPORT_DOMAIN, ETH_RPC_URL/)
})

test("rejects an unknown face match mode", () => {
  assert.throws(() => loadConfig({ ...minimal, ZKPASSPORT_FACEMATCH: "loose" }), /ZKPASSPORT_FACEMATCH/)
  assert.equal(loadConfig({ ...minimal, ZKPASSPORT_FACEMATCH: "off" }).facematch, "off")
})

test("overrides are applied", () => {
  const config = loadConfig({ ...minimal, PORT: "4000", PUBLIC_KEYS_JS_PATH: "/x/public-keys.js" })
  assert.equal(config.port, 4000)
  assert.equal(config.publicKeysJsPath, "/x/public-keys.js")
})
