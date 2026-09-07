const fs = require("node:fs")
const path = require("node:path")
const { classifyProofs, registryContext } = require("./verify")

const BUNDLE_FORMAT = "secure-drop-zkpassport-bundle/1"
const PACKAGES = ["@zkpassport/sdk", "@zkpassport/registry", "@zkpassport/utils", "@aztec/bb.js", "@aztec/bb.js-v4"]
const DEFAULT_VALIDITY_SECONDS = 7 * 24 * 60 * 60 // the SDK default, which we do not override
const CHAIN_ID = 1 // Ethereum mainnet

// The SDK verifies circuits older than 0.20.0 with its bundled bb.js 4.x.
function bbPackageFor(circuitVersion) {
  const [major, minor] = circuitVersion.split(".").map(Number)
  return major === 0 && minor < 20 ? "@aztec/bb.js-v4" : "@aztec/bb.js"
}

// Exact versions installed alongside this file, for the bundle's software record.
function installedVersions() {
  const versions = {}
  for (const name of PACKAGES) {
    const file = path.join(__dirname, "..", "node_modules", name, "package.json")
    versions[name] = JSON.parse(fs.readFileSync(file, "utf8")).version
  }
  return versions
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
    row("First name:", fields.firstname),
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
    binding: {
      domain: config.domain,
      scope: config.scope,
      facematch: config.facematch,
      validitySeconds: DEFAULT_VALIDITY_SECONDS,
      chainId: CHAIN_ID,
    },
    software: {
      ...installedVersions(),
      circuitVersion,
      verifiedWith: bbPackageFor(circuitVersion),
      "secure-drop-verifier": config.gitSha,
    },
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

module.exports = { fieldsBlock, buildBundle, formatTimestamp, bbPackageFor, BUNDLE_FORMAT }
