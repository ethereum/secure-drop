const { test } = require("node:test")
const assert = require("node:assert/strict")
const { createVerifier, MAX_PROOFS, MRZ_LENGTH } = require("../src/verify")
const { DISCLOSED_FIELDS } = require("../src/query")

const settings = { domain: "secure-drop.ethereum.org", scope: "ef-onboarding", facematch: "strict" }

// A passport's machine-readable zone for JANE ANN DOE, Irish, born 1990-05-17,
// expiring 2031-01-02, as the byte array the proof commits to.
function mrzBytes({ documentCode = "P<", name = "DOE<<JANE<ANN" } = {}) {
  const line1 = (documentCode + "IRL" + name + "<".repeat(44)).slice(0, 44)
  const line2 = "P12345678" + "4" + "IRL" + "900517" + "3" + "F" + "310102" + "7" + "<".repeat(14) + "<" + "6"
  return Array.from(new TextEncoder().encode(line1 + line2))
}

// The proof array the app produces in default mode, after a JSON round trip.
function sampleProofs(disclosedBytes = mrzBytes()) {
  return JSON.parse(
    JSON.stringify([
      { proof: "0x01", name: "sig_check_dsc_tbs_1000_rsa_pkcs_2048_sha256", version: "1.0.0" },
      { proof: "0x02", name: "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256", version: "1.0.0" },
      { proof: "0x03", name: "data_check_integrity_sa_sha256_dg_sha256", version: "1.0.0" },
      { proof: "0x04", name: "disclose_bytes", version: "1.0.0", committedInputs: { disclose_bytes: { discloseMask: [], disclosedBytes } } },
      { proof: "0x05", name: "facematch", version: "1.0.0" },
    ]),
  )
}

// What the phone says it disclosed. Deliberately different from the proof
// bytes so the tests can show it is never what legal receives.
const clientResult = {
  fullname: { disclose: { result: "JANE ANN DOE\nNationality: GBR" } },
  birthdate: { disclose: { result: "1990-05-16T05:00:00.000Z" } },
  document_type: { disclose: { result: "passport" }, eq: { expected: "passport", result: true } },
}

function fakeSdk(verified) {
  const calls = []
  return {
    calls,
    async verify(args) {
      calls.push(args)
      return { verified, uniqueIdentifier: "0xnullifier", uniqueIdentifierType: "salted" }
    },
  }
}

test("rejects malformed input before calling the SDK", async () => {
  const sdk = fakeSdk(true)
  const { verifyProof } = createVerifier({ ...settings, zkPassport: sdk })
  const good = sampleProofs()
  const bad = [
    { proofs: [], queryResult: {} },
    { proofs: "not an array", queryResult: {} },
    { proofs: good, queryResult: null },
    { proofs: Array(MAX_PROOFS + 1).fill(good[0]), queryResult: {} },
    { proofs: good.map((p) => ({ ...p, version: undefined })), queryResult: {} },
    { proofs: good.map((p) => ({ ...p, name: p.name.replace("disclose_bytes", "disclose_bytes_evm") })), queryResult: {} },
    { proofs: good.filter((p) => !p.committedInputs), queryResult: {} },
    { proofs: [...good, good[3]], queryResult: {} },
    { proofs: sampleProofs(mrzBytes().slice(0, MRZ_LENGTH - 1)), queryResult: {} },
    { proofs: sampleProofs(mrzBytes().map(String)), queryResult: {} },
  ]
  for (const input of bad) {
    assert.deepEqual(await verifyProof(input), { verified: false })
  }
  assert.equal(sdk.calls.length, 0)
})

test("passes the server's query and scope, never the client's", async () => {
  const sdk = fakeSdk(true)
  const { verifyProof, expectedQuery } = createVerifier({ ...settings, zkPassport: sdk })
  await verifyProof({ proofs: sampleProofs(), queryResult: clientResult })
  assert.equal(sdk.calls.length, 1)
  assert.deepEqual(sdk.calls[0].originalQuery, expectedQuery)
  assert.equal(sdk.calls[0].scope, "ef-onboarding")
  assert.equal(sdk.calls[0].validity, undefined)
})

test("fields come from the proof's bytes, not the client's result", async () => {
  const { verifyProof } = createVerifier({ ...settings, zkPassport: fakeSdk(true) })
  const out = await verifyProof({ proofs: sampleProofs(), queryResult: clientResult })
  assert.deepEqual(Object.keys(out), ["verified", "fields"])
  assert.deepEqual(out.fields, {
    fullname: "JANE ANN DOE",
    firstname: "JANE",
    lastname: "DOE",
    birthdate: "1990-05-17",
    nationality: "IRL",
    gender: "female",
    document_number: "P12345678",
    expiry_date: "2031-01-02",
    issuing_country: "IRL",
    document_type: "passport",
  })
  assert.deepEqual(Object.keys(out.fields).sort(), [...DISCLOSED_FIELDS].sort())
  assert.ok(!JSON.stringify(out).includes("nullifier"))
  assert.ok(!JSON.stringify(out).includes("GBR"))
})

test("an unverified proof yields only verified:false", async () => {
  const { verifyProof } = createVerifier({ ...settings, zkPassport: fakeSdk(false) })
  assert.deepEqual(await verifyProof({ proofs: sampleProofs(), queryResult: clientResult }), { verified: false })
})

test("a non-passport document or a masked field is rejected even if the SDK says verified", async () => {
  const { verifyProof } = createVerifier({ ...settings, zkPassport: fakeSdk(true) })
  const idCard = sampleProofs(mrzBytes({ documentCode: "I<" }))
  assert.deepEqual(await verifyProof({ proofs: idCard, queryResult: clientResult }), { verified: false })
  const maskedName = mrzBytes()
  for (let i = 5; i < 44; i++) maskedName[i] = 0
  assert.deepEqual(await verifyProof({ proofs: sampleProofs(maskedName), queryResult: clientResult }), { verified: false })
})

test("malformed data that breaks inside the SDK is not verified; outages propagate", async () => {
  const throwing = (error) => ({ verify: async () => { throw error } })
  let { verifyProof } = createVerifier({ ...settings, zkPassport: throwing(new TypeError("Cannot read properties of undefined")) })
  assert.deepEqual(await verifyProof({ proofs: sampleProofs(), queryResult: clientResult }), { verified: false })
  ;({ verifyProof } = createVerifier({ ...settings, zkPassport: throwing(new RangeError("Invalid time value")) }))
  assert.deepEqual(await verifyProof({ proofs: sampleProofs(), queryResult: clientResult }), { verified: false })
  ;({ verifyProof } = createVerifier({ ...settings, zkPassport: throwing(new Error("registry unreachable")) }))
  await assert.rejects(verifyProof({ proofs: sampleProofs(), queryResult: clientResult }), /registry unreachable/)
})

test("verifications run one at a time", async () => {
  let release
  let running = 0
  let maxRunning = 0
  const sdk = {
    async verify() {
      running++
      maxRunning = Math.max(maxRunning, running)
      await new Promise((resolve) => (release = resolve))
      running--
      return { verified: false }
    },
  }
  const { verifyProof } = createVerifier({ ...settings, zkPassport: sdk })
  const first = verifyProof({ proofs: sampleProofs(), queryResult: clientResult })
  const second = verifyProof({ proofs: sampleProofs(), queryResult: clientResult })
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(running, 1)
  release()
  await first
  await new Promise((resolve) => setImmediate(resolve))
  release()
  await second
  assert.equal(maxRunning, 1)
})
