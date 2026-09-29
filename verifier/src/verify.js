const util = require("node:util")
const { ZKPassport } = require("@zkpassport/sdk")
const {
  DisclosedData,
  getDiscloseMask,
  getProofData,
  getNumberOfPublicInputs,
  getMerkleRootFromDSCProof,
  getCurrentDateFromDisclosureProof,
} = require("@zkpassport/utils")
const { buildExpectedQuery, DISCLOSED_FIELDS, SCOPE } = require("./query")

const DISCLOSED_BYTES_LENGTH = 90 // the SDK pads a passport's 88-character zone to 90
const PASSPORT_MRZ_LENGTH = 88
const MAX_PROOF_HEX = 256 * 1024 // characters; a real proof is well under 64k
const MAX_QUERY_RESULT_JSON = 64 * 1024
const MAX_QUEUE = 4
const GENDER = { F: "female", M: "male", "<": "unspecified" }

// What our request makes the app produce: one proof for each of these roles,
// face match only when we asked for it, and nothing else.
const ROLES = [
  { role: "certificate", matches: (name) => name.startsWith("sig_check_dsc") },
  { role: "idData", matches: (name) => name.startsWith("sig_check_id_data") },
  { role: "integrity", matches: (name) => name.startsWith("data_check_integrity") },
  { role: "disclosure", matches: (name) => name === "disclose_bytes" },
  // Face match circuits are named by the phone's attestation chain, e.g.
  // facematch_ios or facematch_android_rk_ecdsa_ik_count_1_ik_ecdsa_p256_sha256.
  { role: "facematch", matches: (name) => name.startsWith("facematch") },
]

class BusyError extends Error {
  constructor() {
    super("Verifier is busy")
    this.name = "BusyError"
  }
}

// Raised when verification could not be completed because a service it depends
// on (the registry RPC, the circuits CDN) failed, so the failure is ours, not
// the proof's.
class ServiceUnavailableError extends Error {
  constructor(cause) {
    super("Verification service unavailable")
    this.name = "ServiceUnavailableError"
    this.cause = cause
  }
}

function isBytes(value, length, allowed) {
  return Array.isArray(value) && value.length === length && value.every((b) => Number.isInteger(b) && allowed(b))
}

// The proof string must decode to exactly the public inputs the SDK expects
// for that circuit; otherwise the SDK throws deep inside verification.
function hasExpectedPublicInputs(p) {
  try {
    const { publicInputs } = getProofData(p.proof, getNumberOfPublicInputs(p.name))
    return publicInputs.length === getNumberOfPublicInputs(p.name) && publicInputs.every((x) => /^0x[0-9a-f]{64}$/.test(x))
  } catch {
    return false
  }
}

function wellFormedProof(p) {
  if (!p || typeof p !== "object") return false
  if (typeof p.proof !== "string" || p.proof.length === 0 || p.proof.length > MAX_PROOF_HEX || !/^[0-9a-f]+$/.test(p.proof)) return false
  if (typeof p.name !== "string" || typeof p.version !== "string" || !/^\d+\.\d+\.\d+$/.test(p.version)) return false
  // Our request never produces these. Their names make the SDK verify
  // on-chain through a third-party RPC instead of locally.
  if (p.name.includes("evm")) return false
  return hasExpectedPublicInputs(p)
}

// Maps each proof to its role. Returns null unless every required role is
// filled exactly once and no proof is left over.
function classifyProofs(proofs, facematchOn) {
  if (!Array.isArray(proofs) || !proofs.every(wellFormedProof)) return null
  const required = ROLES.filter((r) => r.role !== "facematch" || facematchOn)
  if (proofs.length !== required.length) return null
  const byRole = {}
  for (const proof of proofs) {
    const found = required.find((r) => r.matches(proof.name))
    if (!found || byRole[found.role]) return null
    byRole[found.role] = proof
  }
  return byRole
}

// The mask the SDK builds for our query on a passport: every field we ask for
// is revealed, the check digits and the unused tail are not.
function expectedMaskFor(expectedQuery) {
  return getDiscloseMask({ mrz: "x".repeat(PASSPORT_MRZ_LENGTH) }, expectedQuery)
}

// The disclosure proof must commit to exactly the bytes our query reveals: a
// different mask means a prover that hid part of a field.
function disclosedBytesOf(disclosureProof, expectedMask) {
  const inputs = disclosureProof.committedInputs?.disclose_bytes
  if (!inputs || !isBytes(inputs.disclosedBytes, DISCLOSED_BYTES_LENGTH, (b) => b >= 0 && b <= 255)) return null
  if (!isBytes(inputs.discloseMask, DISCLOSED_BYTES_LENGTH, (b) => b === 0 || b === 1)) return null
  if (inputs.discloseMask.some((bit, i) => bit !== expectedMask[i])) return null
  if (inputs.disclosedBytes.some((byte, i) => expectedMask[i] === 0 && byte !== 0)) return null
  return inputs.disclosedBytes
}

// Checks that the request is the proof set our query produces. Returns
// { roles, disclosedBytes } when it is, so the caller need not decode the
// proofs again, or { problem } saying why not in a sentence legal can forward.
function shapeCheck({ proofs, queryResult }, facematch, expectedMask) {
  const roles = classifyProofs(proofs, facematch !== "off")
  if (!roles) return { problem: "the request does not contain exactly the proof set our query produces" }
  const disclosedBytes = disclosedBytesOf(roles.disclosure, expectedMask)
  if (disclosedBytes === null) return { problem: "the disclosure proof does not commit to the bytes our query reveals" }
  if (roles.facematch && roles.facematch.committedInputs?.facematch?.mode !== facematch) return { problem: `the face match proof was not made in ${facematch} mode` }
  if (queryResult === null || typeof queryResult !== "object") return { problem: "queryResult is not an object" }
  if (JSON.stringify(queryResult).length > MAX_QUERY_RESULT_JSON) return { problem: "queryResult is too large" }
  return { roles, disclosedBytes }
}

// The SDK explains a rejection only through console.warn, which it keeps
// doing: the lines still reach stderr as before, and are also collected here
// so they can travel to legal. Verifications run one at a time, so lines
// printed during this task come from this request; the bookkeeping other
// requests do concurrently (registry lookups, encryption) does not warn.
async function withCapturedWarnings(task) {
  const warnings = []
  const original = console.warn
  console.warn = (...args) => {
    warnings.push(util.format(...args))
    original.apply(console, args)
  }
  try {
    return { result: await task(), warnings }
  } finally {
    console.warn = original
  }
}

// YYMMDD from the passport zone to YYYY-MM-DD. Two-digit years are read as
// this century unless that puts a birth date in the future. Returns null
// unless the digits form a real calendar date.
function mrzDate(bytes, offset, { past }, today) {
  const text = String.fromCharCode(...bytes.slice(offset, offset + 6))
  if (!/^\d{6}$/.test(text)) return null
  const [yy, mm, dd] = [text.slice(0, 2), text.slice(2, 4), text.slice(4, 6)].map(Number)
  let year = 2000 + yy
  let date = new Date(Date.UTC(year, mm - 1, dd))
  if (past && date > today) {
    year -= 100
    date = new Date(Date.UTC(year, mm - 1, dd))
  }
  const valid = date.getUTCFullYear() === year && date.getUTCMonth() === mm - 1 && date.getUTCDate() === dd
  return valid ? date.toISOString().slice(0, 10) : null
}

// Rebuilds the disclosed fields from the bytes the proof commits to, never from
// the client's own description of them. Returns null if anything is missing
// or implausible.
function fieldsFromProof(disclosedBytes, today = new Date()) {
  const data = DisclosedData.fromDisclosedBytes(disclosedBytes, "passport")
  const fields = {
    fullname: data.name,
    firstname: data.firstName,
    lastname: data.lastName,
    birthdate: mrzDate(disclosedBytes, 57, { past: true }, today),
    nationality: data.nationality,
    gender: GENDER[String.fromCharCode(disclosedBytes[64])],
    document_number: data.documentNumber,
    expiry_date: mrzDate(disclosedBytes, 65, { past: false }, today),
    issuing_country: data.issuingCountry,
    document_type: data.documentType,
  }
  // Every field must be present. The one exception is the first name: a
  // passport issued to a person with a single name has a surname and no
  // given names, and that is a valid passport, not a broken proof.
  for (const name of DISCLOSED_FIELDS) {
    if (typeof fields[name] !== "string") return null
    if (fields[name] === "" && name !== "firstname") return null
  }
  return fields
}

function publicInputsOf(proof) {
  return getProofData(proof.proof, getNumberOfPublicInputs(proof.name))
}

// The certificate registry root the proof was built against, and the proof's
// own date, both read from public inputs. Exported for the bundle.
function registryContext(roles) {
  const root = "0x" + getMerkleRootFromDSCProof(publicInputsOf(roles.certificate)).toString(16).padStart(64, "0")
  const proofDate = getCurrentDateFromDisclosureProof(publicInputsOf(roles.disclosure))
  return { root, proofDate }
}

// Every eq in the expected query must hold for the derived fields.
function satisfiesConstraints(fields, expectedQuery) {
  return Object.entries(expectedQuery).every(([name, rule]) => rule?.eq === undefined || fields[name] === rule.eq)
}

// `checkCertificateRoot(root, timestampSeconds)` asks the on-chain registry
// whether a root was valid at that time. The SDK swallows RPC failures on this
// same check into "not verified", so after a clean SDK rejection the sidecar
// repeats it: a throw means the RPC is down (our problem), an answer means the
// rejection stands.
function createVerifier({ domain, facematch, cacheDir = "/tmp/zkp", zkPassport = new ZKPassport(domain), checkCertificateRoot = async () => true }) {
  const expectedQuery = buildExpectedQuery({ domain, facematch })
  const expectedMask = expectedMaskFor(expectedQuery)
  let queue = Promise.resolve()
  let waiting = 0

  // The WASM verifier is heavy and its first run writes shared cache files, so
  // verifications run one at a time, with a short line behind them.
  function serialized(task) {
    if (waiting >= MAX_QUEUE) throw new BusyError()
    waiting++
    const run = queue.then(task).finally(() => waiting--)
    queue = run.catch(() => {})
    return run
  }

  // Resolves { verified: true, fields } or { verified: false, diagnostics },
  // where diagnostics says how far the request got ("shape", "sdk", "fields",
  // "constraints") and why it stopped. Diagnostics may quote client data, so
  // the caller encrypts them for legal and never returns them in the clear.
  // Throws BusyError when the line is full and ServiceUnavailableError when a
  // service the verification depends on failed.
  async function verifyProof({ proofs, queryResult }) {
    const rejected = (stage, details = {}) => ({ verified: false, diagnostics: { stage, reasons: [], ...details } })

    const shape = shapeCheck({ proofs, queryResult }, facematch, expectedMask)
    if (shape.problem) return rejected("shape", { reasons: [shape.problem] })
    const { roles, disclosedBytes } = shape

    let result, warnings
    try {
      // originalQuery is ours, never the client's. verifierMode "local" keeps
      // verification in this process; the default falls back to zkPassport's
      // hosted verifier and would send the disclosed fields there.
      ;({ result, warnings } = await serialized(() =>
        withCapturedWarnings(() =>
          zkPassport.verify({ proofs, originalQuery: expectedQuery, queryResult, scope: SCOPE, verifierMode: "local", writingDirectory: cacheDir }),
        ),
      ))
    } catch (error) {
      if (error instanceof BusyError) throw error
      // The shape checks above stop client data from breaking the SDK, so an
      // exception here means a fetch or RPC failed inside it.
      throw new ServiceUnavailableError(error)
    }
    if (!result.verified) {
      const { root, proofDate } = registryContext(roles)
      let rootValid
      try {
        rootValid = await checkCertificateRoot(root, Math.floor(proofDate.getTime() / 1000))
      } catch (error) {
        throw new ServiceUnavailableError(error)
      }
      return rejected("sdk", {
        reasons: warnings,
        queryResultErrors: result.queryResultErrors ?? null,
        rootCheck: { root, proofDate: proofDate.toISOString(), valid: rootValid },
      })
    }

    const fields = fieldsFromProof(disclosedBytes)
    if (!fields) return rejected("fields", { reasons: ["the disclosed bytes do not form a complete passport record", ...warnings] })
    if (!satisfiesConstraints(fields, expectedQuery)) return rejected("constraints", { reasons: ["a disclosed field does not satisfy the query, e.g. the document is not a passport", ...warnings] })
    return { verified: true, fields }
  }

  return { verifyProof, expectedQuery, expectedMask }
}

module.exports = {
  createVerifier,
  classifyProofs,
  wellFormedProof,
  shapeCheck,
  fieldsFromProof,
  expectedMaskFor,
  registryContext,
  BusyError,
  ServiceUnavailableError,
  DISCLOSED_BYTES_LENGTH,
  MAX_QUEUE,
}
