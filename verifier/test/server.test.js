const { test, before, after } = require("node:test")
const assert = require("node:assert/strict")
const http = require("node:http")
const openpgp = require("openpgp")
const { createApp, MAX_BODY_BYTES } = require("../src/server")
const { BusyError } = require("../src/verify")
const { settings, sampleProofs, clientResult, expectedFields } = require("./fixtures")

const manifest = { version: "1.0.0", root: "0xmanifestroot", circuits: Object.fromEntries(sampleProofs().map((p) => [p.name, { hash: `0xhash-${p.name}`, size: 1 }])) }
const fakeRegistry = {
  async getCircuitManifest() { return manifest },
  async getCertificateRegistryAddress() { return "0xcert" },
  async getCircuitRegistryAddress() { return "0xcirc" },
  getRootRegistryAddress() { return "0xroot" },
}

let keys
let server
let baseUrl
let logs
let behaviour // what the fake verifier does on the next call

before(async () => {
  keys = await openpgp.generateKey({ type: "ecc", curve: "curve25519", userIDs: [{ name: "legal test" }], format: "object" })
  logs = []
  const verifier = {
    expectedQuery: { fullname: { disclose: true } },
    async verifyProof() {
      if (behaviour instanceof Error) throw behaviour
      return behaviour
    },
  }
  const app = createApp({ config: settings, legalKey: keys.publicKey, verifier, registryClient: fakeRegistry, log: (line) => logs.push(line) })
  server = http.createServer(app)
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve))
  baseUrl = `http://127.0.0.1:${server.address().port}`
})

after(() => server.close())

async function post(path, body, raw = false) {
  const res = await fetch(baseUrl + path, { method: "POST", headers: { "content-type": "application/json" }, body: raw ? body : JSON.stringify(body) })
  return { status: res.status, body: await res.json() }
}

async function decrypt(armored) {
  const { data } = await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: armored }), decryptionKeys: keys.privateKey })
  return data
}

const submission = () => ({ proofs: sampleProofs(), queryResult: clientResult, identifier: "legal:2026:09:06:10:00:00:1234", reference: "FY26-1234" })

test("health and unknown routes", async () => {
  const health = await fetch(baseUrl + "/health")
  assert.equal(health.status, 200)
  assert.deepEqual(await health.json(), { status: "ok" })
  assert.equal((await fetch(baseUrl + "/verify")).status, 404)
  assert.equal((await post("/other", {})).status, 404)
})

test("bad requests", async () => {
  assert.deepEqual(await post("/verify", "{not json", true), { status: 400, body: { error: "bad_request" } })
  assert.deepEqual(await post("/verify", { ...submission(), identifier: undefined }), { status: 400, body: { error: "bad_request" } })
  assert.deepEqual(await post("/verify", { ...submission(), identifier: "x".repeat(201) }), { status: 400, body: { error: "bad_request" } })
  const huge = await post("/verify", JSON.stringify({ ...submission(), pad: "x".repeat(MAX_BODY_BYTES) }), true).catch((e) => ({ status: "closed", body: e.message }))
  assert.ok(huge.status === 413 || huge.status === "closed")
})

test("a proof that does not verify yields verified:false and nothing else", async () => {
  behaviour = { verified: false }
  assert.deepEqual(await post("/verify", submission()), { status: 200, body: { verified: false } })
})

test("a verified proof yields both blocks encrypted to the legal key", async () => {
  behaviour = { verified: true, fields: expectedFields }
  logs.length = 0
  const { status, body } = await post("/verify", submission())
  assert.equal(status, 200)
  assert.equal(body.verified, true)
  assert.deepEqual(Object.keys(body).sort(), ["bundleArmored", "fieldsBlockArmored", "verified"])

  const block = await decrypt(body.fieldsBlockArmored)
  assert.match(block, /^Passport fields verified with zkPassport\n/)
  assert.match(block, /Submission: +legal:2026:09:06:10:00:00:1234/)
  assert.match(block, /Full name: +JANE ANN DOE/)
  assert.match(block, /FaceMatch: +strict/)

  const bundle = JSON.parse(await decrypt(body.bundleArmored))
  assert.equal(bundle.submission.identifier, "legal:2026:09:06:10:00:00:1234")
  assert.equal(bundle.submission.reference, "FY26-1234")
  assert.deepEqual(bundle.query, { fullname: { disclose: true } })
  assert.deepEqual(bundle.artifacts.circuitManifest, manifest)

  for (const value of Object.values(expectedFields)) {
    assert.ok(!body.fieldsBlockArmored.includes(value) && !body.bundleArmored.includes(value), `${value} must not appear in ciphertext`)
    assert.ok(!logs.join("\n").includes(value), `${value} must not appear in logs`)
  }
  assert.match(logs.join("\n"), /verified \(\d+ ms\)/)
})

test("busy and failing verifier map to 503 and 500", async () => {
  behaviour = new BusyError()
  assert.deepEqual(await post("/verify", submission()), { status: 503, body: { error: "busy" } })
  behaviour = new TypeError("fetch failed")
  assert.deepEqual(await post("/verify", submission()), { status: 500, body: { error: "verification_error" } })
})
