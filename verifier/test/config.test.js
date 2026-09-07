const { test } = require("node:test")
const assert = require("node:assert/strict")
const { loadConfig, FACEMATCH_MODES } = require("../src/config")

const minimal = {
  ZKPASSPORT_DOMAIN: "localhost",
  ZKPASSPORT_SCOPE: "ef-onboarding",
}

test("loads with defaults", () => {
  assert.deepEqual(loadConfig(minimal), {
    port: 3000,
    domain: "localhost",
    scope: "ef-onboarding",
    facematch: "strict",
    publicKeysJsPath: "/app/static/js/public-keys.js",
    gitSha: "unknown",
  })
})

test("reports every missing variable at once", () => {
  assert.throws(() => loadConfig({}), /ZKPASSPORT_DOMAIN, ZKPASSPORT_SCOPE/)
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

test("overrides are applied", () => {
  assert.equal(loadConfig({ ...minimal, PUBLIC_KEYS_JS_PATH: "/x/public-keys.js" }).publicKeysJsPath, "/x/public-keys.js")
})
