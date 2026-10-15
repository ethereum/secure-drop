const { test } = require("node:test")
const assert = require("node:assert/strict")
const { loadConfig, FACEMATCH_MODES } = require("../src/config")

const minimal = {
  ZKPASSPORT_DOMAIN: "localhost",
}

test("loads with defaults", () => {
  assert.deepEqual(loadConfig(minimal), {
    port: 3000,
    domain: "localhost",
    facematch: "strict",
    publicKeysJsPath: "/app/static/js/public-keys.js",
    cacheDir: "/tmp/zkp",
    crsPath: "/tmp/zkp/.bb-crs",
    rpcUrl: undefined,
    gitSha: "unknown",
  })
})

test("reports a missing variable", () => {
  assert.throws(() => loadConfig({}), /ZKPASSPORT_DOMAIN/)
})

test("validates the face match mode", () => {
  assert.deepEqual(FACEMATCH_MODES, ["strict", "regular", "off"])
  assert.throws(() => loadConfig({ ...minimal, ZKPASSPORT_FACEMATCH: "loose" }), /ZKPASSPORT_FACEMATCH/)
  assert.equal(loadConfig({ ...minimal, ZKPASSPORT_FACEMATCH: "off" }).facematch, "off")
})

test("validates the port", () => {
  assert.throws(() => loadConfig({ ...minimal, PORT: "abc" }), /PORT/)
  assert.throws(() => loadConfig({ ...minimal, PORT: "0" }), /PORT/)
  assert.throws(() => loadConfig({ ...minimal, PORT: "70000" }), /PORT/)
  assert.equal(loadConfig({ ...minimal, PORT: "4000" }).port, 4000)
})

test("validates the RPC URL and keeps it out of the error", () => {
  assert.equal(loadConfig({ ...minimal, ETH_RPC_URL: "" }).rpcUrl, undefined)
  assert.equal(loadConfig({ ...minimal, ETH_RPC_URL: "https://rpc.example/v1/secret" }).rpcUrl, "https://rpc.example/v1/secret")
  // A secret made from a file usually ends in a newline.
  assert.equal(loadConfig({ ...minimal, ETH_RPC_URL: "https://rpc.example/v1/secret\n" }).rpcUrl, "https://rpc.example/v1/secret")
  assert.equal(loadConfig({ ...minimal, ETH_RPC_URL: "  \n" }).rpcUrl, undefined)
  assert.throws(
    () => loadConfig({ ...minimal, ETH_RPC_URL: "wss://rpc.example/v1/secret" }),
    (error) => /ETH_RPC_URL/.test(error.message) && !error.message.includes("secret"),
  )
})

test("overrides are applied", () => {
  assert.equal(loadConfig({ ...minimal, PUBLIC_KEYS_JS_PATH: "/x/public-keys.js" }).publicKeysJsPath, "/x/public-keys.js")
  const moved = loadConfig({ ...minimal, CACHE_DIR: "/x/cache" })
  assert.equal(moved.cacheDir, "/x/cache")
  assert.equal(moved.crsPath, "/x/cache/.bb-crs")
})
