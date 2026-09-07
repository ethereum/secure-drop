const { test } = require("node:test")
const assert = require("node:assert/strict")
const { buildExpectedQuery, DISCLOSED_FIELDS } = require("../src/query")

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

test("full query shape", () => {
  const disclosed = Object.fromEntries(DISCLOSED_FIELDS.map((f) => [f, { disclose: true }]))
  disclosed.document_type = { disclose: true, eq: "passport" }
  assert.deepEqual(buildExpectedQuery({ domain, facematch: "strict" }), {
    ...disclosed,
    facematch: { mode: "strict" },
  })
})
