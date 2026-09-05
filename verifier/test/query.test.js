const { test } = require("node:test")
const assert = require("node:assert/strict")
const { buildExpectedQuery, DISCLOSED_FIELDS, FACEMATCH_MODES } = require("../src/query")

const domain = "secure-drop.ethereum.org"

test("discloses every field and requires a passport", () => {
  const query = buildExpectedQuery({ domain, facematch: "off" })
  for (const field of DISCLOSED_FIELDS) {
    assert.equal(query[field].disclose, true, `${field} should be disclosed`)
  }
  assert.equal(query.document_type.eq, "passport")
  assert.equal(query.facematch, undefined)
})

test("face match mode is passed through", () => {
  assert.deepEqual(buildExpectedQuery({ domain, facematch: "strict" }).facematch, { mode: "strict" })
  assert.deepEqual(buildExpectedQuery({ domain, facematch: "regular" }).facematch, { mode: "regular" })
})

test("rejects an unknown face match mode", () => {
  assert.throws(() => buildExpectedQuery({ domain, facematch: "loose" }), /ZKPASSPORT_FACEMATCH/)
  assert.throws(() => buildExpectedQuery({ domain, facematch: undefined }), /ZKPASSPORT_FACEMATCH/)
})

test("query shape is exactly what the browser builds", () => {
  const disclosed = Object.fromEntries(DISCLOSED_FIELDS.map((f) => [f, { disclose: true }]))
  disclosed.document_type = { disclose: true, eq: "passport" }
  assert.deepEqual(buildExpectedQuery({ domain, facematch: "strict" }), {
    ...disclosed,
    facematch: { mode: "strict" },
  })
})

test("mode list is what the config table documents", () => {
  assert.deepEqual(FACEMATCH_MODES, ["strict", "regular", "off"])
})
