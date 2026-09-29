const fs = require("node:fs")
const path = require("node:path")
const { classifyProofs, registryContext, wellFormedProof } = require("./verify")
const { SCOPE } = require("./query")

const BUNDLE_FORMAT = "secure-drop-zkpassport-bundle/1"
const FAILURE_FORMAT = "secure-drop-zkpassport-failure/1"
// A failure bundle carries the request only when it is worth replaying: a
// plausible proof set of ordinary size (a real one is a few hundred KB).
const MAX_REPLAY_PROOFS = 8
const MAX_REPLAY_BYTES = 1024 * 1024
const PACKAGES = ["@zkpassport/sdk", "@zkpassport/registry", "@zkpassport/utils", "@aztec/bb.js", "@aztec/bb.js-v4"]
const DEFAULT_VALIDITY_SECONDS = 7 * 24 * 60 * 60 // the SDK default, which we do not override
const CHAIN_ID = 1 // Ethereum mainnet

// The SDK verifies circuits older than 0.20.0 with its bundled bb.js 4.x.
function bbPackageFor(circuitVersion) {
  const [major, minor] = circuitVersion.split(".").map(Number)
  return major === 0 && minor < 20 ? "@aztec/bb.js-v4" : "@aztec/bb.js"
}

// Exact versions installed alongside this file, for the bundle's software
// record. Read once; they cannot change while the process runs.
let versions
function installedVersions() {
  if (!versions) {
    versions = {}
    for (const name of PACKAGES) {
      const file = path.join(__dirname, "..", "node_modules", name, "package.json")
      versions[name] = JSON.parse(fs.readFileSync(file, "utf8")).version
    }
  }
  return { ...versions }
}

// "2026-09-05 14:03 UTC"
function formatTimestamp(date) {
  return date.toISOString().slice(0, 16).replace("T", " ") + " UTC"
}

// The plaintext legal reads after decrypting the fields block.
function fieldsBlock({ fields, identifier, reference, verifiedAt, facematch }) {
  const row = (label, value) => `${label.padEnd(18)}${value}`
  return [
    "Passport fields verified with zkPassport",
    row("Submission:", identifier),
    row("Reference:", reference || "(none)"),
    row("Verified at:", formatTimestamp(verifiedAt)),
    row("FaceMatch:", facematch),
    "",
    row("Full name:", fields.fullname),
    row("First name:", fields.firstname || "(none)"),
    row("Last name:", fields.lastname),
    row("Date of birth:", fields.birthdate),
    row("Nationality:", fields.nationality),
    row("Gender:", fields.gender),
    row("Passport number:", fields.document_number),
    row("Expiry date:", fields.expiry_date),
    row("Issuing country:", fields.issuing_country),
    row("Document type:", fields.document_type),
    "",
    "passport-proof-bundle.json.pgp, attached to the same email, holds the proof",
    "and the data needed to verify it again.",
  ].join("\n")
}

// The settings every proof is checked against, recorded in both bundles.
function bindingFor(config) {
  return {
    domain: config.domain,
    scope: SCOPE,
    facematch: config.facematch,
    validitySeconds: DEFAULT_VALIDITY_SECONDS,
    chainId: CHAIN_ID,
  }
}

// The software that did the checking. circuitVersion may be absent or garbage
// for a request that failed the shape checks.
function softwareFor(config, circuitVersion) {
  const known = typeof circuitVersion === "string" && /^\d+\.\d+\.\d+$/.test(circuitVersion)
  return {
    ...installedVersions(),
    circuitVersion: known ? circuitVersion : null,
    verifiedWith: known ? bbPackageFor(circuitVersion) : null,
    "secure-drop-verifier": config.gitSha,
  }
}

// Why a proof was not accepted, for legal to read and engineering to replay:
// how far it got, the verifier's own messages, and the request as received.
function buildFailureBundle({ proofs, queryResult, expectedQuery, identifier, reference, verifiedAt, config, diagnostics }) {
  const replayable =
    Array.isArray(proofs) && proofs.length > 0 && proofs.length <= MAX_REPLAY_PROOFS && proofs.every(wellFormedProof) && JSON.stringify(proofs).length <= MAX_REPLAY_BYTES
  const queryResultOk = queryResult !== null && typeof queryResult === "object" && JSON.stringify(queryResult).length <= MAX_REPLAY_BYTES
  return {
    format: FAILURE_FORMAT,
    verifiedAt: verifiedAt.toISOString(),
    submission: { identifier, reference },
    stage: diagnostics.stage,
    reasons: diagnostics.reasons,
    queryResultErrors: diagnostics.queryResultErrors ?? null,
    rootCheck: diagnostics.rootCheck ?? null,
    binding: bindingFor(config),
    software: softwareFor(config, Array.isArray(proofs) ? proofs[0]?.version : undefined),
    query: expectedQuery,
    request: {
      replayable,
      proofs: Array.isArray(proofs) ? proofs.map((p) => (p && typeof p === "object" ? String(p.name) : typeof p)) : typeof proofs,
    },
    queryResult: replayable && queryResultOk ? queryResult : undefined,
    proofs: replayable ? proofs : undefined,
    notes:
      "This proof was not accepted. `stage` says how far it got: shape (the request is not the proof set our query produces), sdk (the zkPassport SDK rejected it; `reasons` are its own messages in order and `queryResultErrors` its detail), fields or constraints (the SDK accepted it but the disclosed bytes were not a usable passport record). To reproduce, run the verifier from the secure-drop repo at the recorded git sha with ZKPASSPORT_DOMAIN and ZKPASSPORT_FACEMATCH set to the values under binding, and POST proofs, queryResult, identifier and reference to /verify. The SDK enforces a 7-day validity from the proof date, so replay within that window.",
  }
}

// What is needed to verify this proof again later: the proof, our query, the
// roots it was checked against, the identity of every circuit involved, and the
// software versions that did the checking.
async function buildBundle({ proofs, queryResult, expectedQuery, identifier, reference, verifiedAt, config, registryClient }) {
  const roles = classifyProofs(proofs, config.facematch !== "off")
  if (!roles) throw new Error("Cannot bundle a proof set that did not pass verification checks")
  const { root: certificateRoot, proofDate } = registryContext(roles)
  const circuitVersion = proofs[0].version

  // The manifest names every circuit of this version with its hash. The
  // verification keys themselves are not stored; they can be fetched again by
  // hash from zkPassport's CDN or IPFS, and each proof carries its own vkeyHash.
  const manifest = await registryClient.getCircuitManifest(undefined, { version: circuitVersion })
  const circuits = {}
  for (const proof of proofs) {
    circuits[proof.name] = { circuitHash: manifest.circuits[proof.name]?.hash ?? null, vkeyHash: proof.vkeyHash ?? null }
  }

  return {
    format: BUNDLE_FORMAT,
    verifiedAt: verifiedAt.toISOString(),
    submission: { identifier, reference },
    binding: bindingFor(config),
    software: softwareFor(config, circuitVersion),
    query: expectedQuery,
    queryResult,
    proofs,
    proofDate: proofDate.toISOString(),
    artifacts: {
      circuitManifest: manifest,
      circuits,
      certificateRegistry: {
        root: certificateRoot,
        validAt: proofDate.toISOString(),
        chainId: CHAIN_ID,
        contract: await registryClient.getCertificateRegistryAddress(),
      },
      circuitRegistry: {
        root: manifest.root,
        chainId: CHAIN_ID,
        contract: await registryClient.getCircuitRegistryAddress(),
      },
      rootRegistry: registryClient.getRootRegistryAddress(),
    },
    notes:
      "Re-verify with the secure-drop repo at the recorded git sha. Run the SDK's verify() with query as originalQuery, queryResult, proofs, and scope. The SDK compares the proof date to the current clock, so pass validity = (now - proofDate) + 604800 seconds. The certificate root was valid on the Ethereum mainnet registry at proofDate. Verification keys are not included; fetch them by circuit hash from the circuits CDN or IPFS, or rebuild them from the open-source circuits at circuitVersion.",
  }
}

module.exports = { fieldsBlock, buildBundle, buildFailureBundle, formatTimestamp, bbPackageFor, BUNDLE_FORMAT, FAILURE_FORMAT }
