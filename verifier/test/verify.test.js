const { test } = require("node:test")
const assert = require("node:assert/strict")
const { createVerifier, fieldsFromProof, BusyError, ServiceUnavailableError, DISCLOSED_BYTES_LENGTH, MAX_QUEUE } = require("../src/verify")
const { DISCLOSED_FIELDS } = require("../src/query")
const { settings, expectedMask, certificateRoot, proofDate, mrzBytes, disclosedBytesFor, sampleProofs, clientResult, expectedFields } = require("./fixtures")

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

function rename(proofs, from, to) {
  return proofs.map((p) => (p.name === from ? { ...p, name: to } : p))
}

test("rejects anything that is not the proof set our request produces", async () => {
  const sdk = fakeSdk(true)
  const { verifyProof } = createVerifier({ ...settings, zkPassport: sdk })
  const good = sampleProofs()
  const facematchInputs = good[4].committedInputs
  const bad = [
    { proofs: [], queryResult: {} },
    { proofs: "not an array", queryResult: {} },
    { proofs: good, queryResult: null },
    { proofs: good, queryResult: { pad: "x".repeat(70 * 1024) } },
    { proofs: [...good, good[4]], queryResult: {} }, // extra proof
    { proofs: good.slice(0, 4), queryResult: {} }, // face match proof missing
    { proofs: good.slice(0, 4).map((p, i) => (i === 2 ? { ...p, committedInputs: facematchInputs } : p)), queryResult: {} }, // pasted onto another proof
    { proofs: [good[0], good[0], good[2], good[3], good[4]], queryResult: {} }, // duplicate role
    { proofs: rename(good, "disclose_bytes", "disclose_bytez"), queryResult: {} },
    { proofs: rename(good, "disclose_bytes", "disclose_bytes_evm"), queryResult: {} },
    { proofs: sampleProofs({ facematch: "regular" }), queryResult: {} }, // wrong face match mode
    { proofs: good.map((p) => ({ ...p, version: "1.0" })), queryResult: {} },
    { proofs: good.map((p) => ({ ...p, proof: "0x" + p.proof })), queryResult: {} },
    { proofs: good.map((p) => ({ ...p, proof: "ab".repeat(200 * 1024) })), queryResult: {} },
    { proofs: good.map((p) => ({ ...p, proof: "ab" })), queryResult: {} }, // too short for its public inputs
    { proofs: sampleProofs({ disclosedBytes: disclosedBytesFor(mrzBytes()).slice(0, DISCLOSED_BYTES_LENGTH - 1) }), queryResult: {} },
    { proofs: sampleProofs({ discloseMask: expectedMask.map((b, i) => (i >= 46 && i < 53 ? 0 : b)) }), queryResult: {} }, // part of the passport number hidden
    { proofs: sampleProofs({ discloseMask: expectedMask.map((b, i) => (i === 53 ? 1 : b)) }), queryResult: {} }, // reveals more than asked
    { proofs: sampleProofs({ disclosedBytes: disclosedBytesFor(mrzBytes()).map((b, i) => (i === 53 ? 52 : b)) }), queryResult: {} }, // data where the mask says none
  ]
  for (const input of bad) {
    assert.deepEqual(await verifyProof(input), { verified: false })
  }
  assert.equal(sdk.calls.length, 0)
})

test("face match off means exactly four proofs", async () => {
  const sdk = fakeSdk(true)
  const { verifyProof } = createVerifier({ ...settings, facematch: "off", zkPassport: sdk })
  assert.equal((await verifyProof({ proofs: sampleProofs({ facematch: "off" }), queryResult: clientResult })).verified, true)
  assert.deepEqual(await verifyProof({ proofs: sampleProofs(), queryResult: clientResult }), { verified: false })
  assert.equal(sdk.calls.length, 1)
})

test("passes the server's query and scope, never the client's", async () => {
  const sdk = fakeSdk(true)
  const { verifyProof, expectedQuery } = createVerifier({ ...settings, zkPassport: sdk })
  await verifyProof({ proofs: sampleProofs(), queryResult: clientResult })
  assert.equal(sdk.calls.length, 1)
  assert.deepEqual(sdk.calls[0].originalQuery, expectedQuery)
  assert.equal(sdk.calls[0].scope, "ef-onboarding")
  assert.equal(sdk.calls[0].verifierMode, "local")
  assert.equal(sdk.calls[0].validity, undefined)
})

test("fields come from the proof's bytes, not the client's result", async () => {
  const { verifyProof } = createVerifier({ ...settings, zkPassport: fakeSdk(true) })
  const out = await verifyProof({ proofs: sampleProofs(), queryResult: clientResult })
  assert.deepEqual(Object.keys(out), ["verified", "fields"])
  assert.deepEqual(out.fields, expectedFields)
  assert.deepEqual(Object.keys(out.fields).sort(), [...DISCLOSED_FIELDS].sort())
  assert.ok(!JSON.stringify(out).includes("nullifier"))
  assert.ok(!JSON.stringify(out).includes("GBR"))
})

test("an unverified proof yields only verified:false", async () => {
  const { verifyProof } = createVerifier({ ...settings, zkPassport: fakeSdk(false) })
  assert.deepEqual(await verifyProof({ proofs: sampleProofs(), queryResult: clientResult }), { verified: false })
})

test("a non-passport document or a blank field is rejected even if the SDK says verified", async () => {
  const { verifyProof } = createVerifier({ ...settings, zkPassport: fakeSdk(true) })
  const idCard = sampleProofs({ mrz: mrzBytes({ documentCode: "I<" }) })
  assert.deepEqual(await verifyProof({ proofs: idCard, queryResult: clientResult }), { verified: false })
  const blankName = sampleProofs({ mrz: mrzBytes({ name: "<<" }) })
  assert.deepEqual(await verifyProof({ proofs: blankName, queryResult: clientResult }), { verified: false })
})

test("dates and gender are read from the passport bytes with plausibility checks", () => {
  const today = new Date("2026-09-06T00:00:00Z")
  assert.equal(fieldsFromProof(mrzBytes({ birth: "350517" }), today).birthdate, "1935-05-17")
  assert.equal(fieldsFromProof(mrzBytes({ birth: "200517" }), today).birthdate, "2020-05-17")
  assert.equal(fieldsFromProof(mrzBytes({ birth: "901340" }), today), null)
  assert.equal(fieldsFromProof(mrzBytes({ expiry: "3102301" .slice(0, 6) }), today), null)
  assert.equal(fieldsFromProof(mrzBytes({ birth: "90A517" }), today), null)
  assert.equal(fieldsFromProof(mrzBytes({ sex: "M" }), today).gender, "male")
  assert.equal(fieldsFromProof(mrzBytes({ sex: "<" }), today).gender, "unspecified")
  assert.equal(fieldsFromProof(mrzBytes({ sex: "X" }), today), null)
})

test("an SDK exception is an outage; a clean rejection is confirmed with our own root check", async () => {
  const throwing = (error) => ({ verify: async () => { throw error } })
  const input = () => ({ proofs: sampleProofs(), queryResult: clientResult })

  let verifier = createVerifier({ ...settings, zkPassport: throwing(new TypeError("fetch failed")) })
  await assert.rejects(verifier.verifyProof(input()), ServiceUnavailableError)

  const checks = []
  const rootCheck = (answer) => async (root, timestamp) => { checks.push({ root, timestamp }); if (answer instanceof Error) throw answer; return answer }

  verifier = createVerifier({ ...settings, zkPassport: fakeSdk(false), checkCertificateRoot: rootCheck(true) })
  assert.deepEqual(await verifier.verifyProof(input()), { verified: false })
  assert.equal(checks.length, 1)
  assert.equal(checks[0].root, "0x" + certificateRoot.toString(16).padStart(64, "0"))
  assert.equal(checks[0].timestamp, Math.floor(proofDate.getTime() / 1000))

  verifier = createVerifier({ ...settings, zkPassport: fakeSdk(false), checkCertificateRoot: rootCheck(false) })
  assert.deepEqual(await verifier.verifyProof(input()), { verified: false })

  verifier = createVerifier({ ...settings, zkPassport: fakeSdk(false), checkCertificateRoot: rootCheck(new Error("rpc down")) })
  await assert.rejects(verifier.verifyProof(input()), ServiceUnavailableError)

  checks.length = 0
  verifier = createVerifier({ ...settings, zkPassport: fakeSdk(true), checkCertificateRoot: rootCheck(true) })
  assert.equal((await verifier.verifyProof(input())).verified, true)
  assert.equal(checks.length, 0, "the root check only runs after a rejection")
})

test("verifications run one at a time and the line is bounded", async () => {
  const releases = []
  let running = 0
  let maxRunning = 0
  const sdk = {
    async verify() {
      running++
      maxRunning = Math.max(maxRunning, running)
      await new Promise((resolve) => releases.push(resolve))
      running--
      return { verified: false }
    },
  }
  const { verifyProof } = createVerifier({ ...settings, zkPassport: sdk })
  const input = () => ({ proofs: sampleProofs(), queryResult: clientResult })
  const pending = Array.from({ length: MAX_QUEUE }, () => verifyProof(input()))
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(running, 1)
  await assert.rejects(verifyProof(input()), BusyError)
  for (let i = 0; i < MAX_QUEUE; i++) {
    await new Promise((resolve) => setImmediate(resolve))
    assert.equal(releases.length, 1)
    releases.shift()()
  }
  await Promise.all(pending)
  assert.equal(maxRunning, 1)
})
