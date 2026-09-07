const { test } = require("node:test")
const assert = require("node:assert/strict")
const { fieldsBlock, buildBundle, formatTimestamp, bbPackageFor, BUNDLE_FORMAT } = require("../src/bundle")
const { settings, proofDate, certificateRoot, sampleProofs, expectedFields } = require("./fixtures")

const verifiedAt = new Date("2026-09-05T14:03:22Z")
const proofs = sampleProofs()

const manifest = {
  version: "1.0.0",
  root: "0xmanifestroot",
  circuits: Object.fromEntries(proofs.map((p) => [p.name, { hash: `0xhash-${p.name}`, size: 1 }])),
}

const fakeRegistry = {
  async getCircuitManifest(root, { version }) {
    assert.equal(root, undefined)
    assert.equal(version, "1.0.0")
    return manifest
  },
  async getPackagedCircuit() {
    throw new Error("the bundle must not download packaged circuits")
  },
  async getCertificateRegistryAddress() { return "0xcert" },
  async getCircuitRegistryAddress() { return "0xcirc" },
  getRootRegistryAddress() { return "0xroot" },
}

test("timestamp format", () => {
  assert.equal(formatTimestamp(verifiedAt), "2026-09-05 14:03 UTC")
})

test("bb.js selection follows the SDK's circuit version threshold", () => {
  assert.equal(bbPackageFor("0.19.9"), "@aztec/bb.js-v4")
  assert.equal(bbPackageFor("0.20.0"), "@aztec/bb.js")
  assert.equal(bbPackageFor("1.0.0"), "@aztec/bb.js")
})

test("fields block reads as specified", () => {
  const block = fieldsBlock({ fields: expectedFields, identifier: "legal:2026:09:05:14:03:22:4821", reference: "FY26-1234", verifiedAt, facematch: "strict" })
  assert.deepEqual(block.split("\n"), [
    "Passport fields verified with zkPassport",
    "Submission:       legal:2026:09:05:14:03:22:4821",
    "Reference:        FY26-1234",
    "Verified at:      2026-09-05 14:03 UTC",
    "FaceMatch:        strict",
    "",
    "Full name:        JANE ANN DOE",
    "First name:       JANE",
    "Last name:        DOE",
    "Date of birth:    1990-05-17",
    "Nationality:      IRL",
    "Gender:           female",
    "Passport number:  P12345678",
    "Expiry date:      2031-01-02",
    "Issuing country:  IRL",
    "Document type:    passport",
    "",
    "The attached passport-proof-bundle.json.pgp holds the proof and the data",
    "needed to verify it again.",
  ])
  assert.match(fieldsBlock({ fields: expectedFields, identifier: "x", reference: "", verifiedAt, facematch: "off" }), /Reference: +\(none\)/)
})

test("bundle records what the proof says and what verified it", async () => {
  const expectedQuery = { fullname: { disclose: true } }
  const queryResult = { fullname: { disclose: { result: "JANE ANN DOE" } } }
  const bundle = await buildBundle({
    proofs, queryResult, expectedQuery, identifier: "legal:2026:09:05:14:03:22:4821", reference: "FY26-1234", verifiedAt, config: settings, registryClient: fakeRegistry,
  })

  assert.equal(bundle.format, BUNDLE_FORMAT)
  assert.equal(bundle.verifiedAt, "2026-09-05T14:03:22.000Z")
  assert.equal(bundle.proofDate, proofDate.toISOString())
  assert.deepEqual(bundle.submission, { identifier: "legal:2026:09:05:14:03:22:4821", reference: "FY26-1234" })
  assert.deepEqual(bundle.binding, { domain: settings.domain, scope: settings.scope, facematch: "strict", validitySeconds: 604800, chainId: 1 })
  assert.equal(bundle.query, expectedQuery)
  assert.equal(bundle.queryResult, queryResult)
  assert.equal(bundle.proofs, proofs)

  const installed = (name) => JSON.parse(require("node:fs").readFileSync(require("node:path").join(__dirname, "..", "node_modules", name, "package.json"), "utf8")).version
  assert.equal(bundle.software["@zkpassport/sdk"], installed("@zkpassport/sdk"))
  assert.match(bundle.software["@zkpassport/sdk"], /^0\.17\./)
  assert.equal(bundle.software["@aztec/bb.js"], "5.0.0")
  assert.match(bundle.software["@aztec/bb.js-v4"], /^4\./)
  assert.equal(bundle.software.verifiedWith, "@aztec/bb.js")
  assert.equal(bundle.software.circuitVersion, "1.0.0")
  assert.equal(bundle.software["secure-drop-verifier"], "abc1234")

  assert.deepEqual(bundle.artifacts.certificateRegistry, {
    root: "0x" + certificateRoot.toString(16).padStart(64, "0"), validAt: bundle.proofDate, chainId: 1, contract: "0xcert",
  })
  assert.deepEqual(bundle.artifacts.circuitRegistry, { root: "0xmanifestroot", chainId: 1, contract: "0xcirc" })
  assert.equal(bundle.artifacts.rootRegistry, "0xroot")
  assert.equal(bundle.artifacts.circuitManifest, manifest)

  assert.deepEqual(Object.keys(bundle.artifacts.circuits).sort(), proofs.map((p) => p.name).sort())
  const fm = "facematch_ios_rk_ecdsa_ik_count_1_ik_ecdsa_p256_sha256"
  assert.deepEqual(bundle.artifacts.circuits[fm], { circuitHash: `0xhash-${fm}`, vkeyHash: `0xvk-${fm}` })
  assert.equal(bundle.artifacts.verificationKeys, undefined)

  const json = JSON.stringify(bundle)
  assert.ok(json.length < 1024 * 1024)
  assert.deepEqual(JSON.parse(json).submission, bundle.submission)
})

test("refuses to bundle a proof set that would not verify", async () => {
  await assert.rejects(
    buildBundle({ proofs: proofs.slice(0, 4), queryResult: {}, expectedQuery: {}, identifier: "x", reference: "", verifiedAt, config: settings, registryClient: fakeRegistry }),
    /did not pass/,
  )
})
