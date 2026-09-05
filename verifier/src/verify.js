const { ZKPassport } = require("@zkpassport/sdk")
const { DisclosedData } = require("@zkpassport/utils")
const { buildExpectedQuery, DISCLOSED_FIELDS } = require("./query")

const MAX_PROOFS = 8
const MRZ_LENGTH = 88 // two 44-character lines of a passport's machine-readable zone
const GENDER = { F: "female", M: "male" }

function isByteArray(value, length) {
  return Array.isArray(value) && value.length === length && value.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)
}

// The passport bytes the proof commits to. Exactly one proof carries them.
function disclosedBytesOf(proofs) {
  const carriers = proofs.filter((p) => p.committedInputs?.disclose_bytes?.disclosedBytes !== undefined)
  if (carriers.length !== 1) return null
  const bytes = carriers[0].committedInputs.disclose_bytes.disclosedBytes
  return isByteArray(bytes, MRZ_LENGTH) ? bytes : null
}

// Cheap shape checks before anything expensive runs.
function looksLikeProofSubmission({ proofs, queryResult }) {
  if (!Array.isArray(proofs) || proofs.length === 0 || proofs.length > MAX_PROOFS) return false
  for (const p of proofs) {
    if (!p || typeof p !== "object") return false
    if (typeof p.proof !== "string" || typeof p.name !== "string" || typeof p.version !== "string") return false
    // Our request never produces these. Their names make the SDK verify
    // on-chain through a third-party RPC instead of locally.
    if (p.name.includes("evm")) return false
  }
  if (disclosedBytesOf(proofs) === null) return false
  return queryResult !== null && typeof queryResult === "object"
}

function toDay(date) {
  return date instanceof Date && !Number.isNaN(date.getTime()) ? date.toISOString().slice(0, 10) : ""
}

// Rebuilds the disclosed fields from the bytes the proof commits to, never from
// the client's own description of them. Returns null if any field is empty.
function fieldsFromProof(disclosedBytes) {
  const data = DisclosedData.fromDisclosedBytes(disclosedBytes, "passport")
  const fields = {
    fullname: data.name,
    firstname: data.firstName,
    lastname: data.lastName,
    birthdate: toDay(data.dateOfBirth),
    nationality: data.nationality,
    gender: GENDER[data.gender] ?? data.gender,
    document_number: data.documentNumber,
    expiry_date: toDay(data.dateOfExpiry),
    issuing_country: data.issuingCountry,
    document_type: data.documentType,
  }
  for (const name of DISCLOSED_FIELDS) {
    if (typeof fields[name] !== "string" || fields[name] === "") return null
  }
  return fields
}

// Every eq in the expected query must hold for the derived fields.
function satisfiesConstraints(fields, expectedQuery) {
  return Object.entries(expectedQuery).every(([name, rule]) => rule?.eq === undefined || fields[name] === rule.eq)
}

// Malformed client data surfaces inside the SDK as one of these. Anything else
// (network, registry, RPC) is an outage and is rethrown.
function isInputError(error) {
  return error instanceof TypeError || error instanceof RangeError || error instanceof SyntaxError
}

function createVerifier({ domain, scope, facematch, zkPassport = new ZKPassport(domain) }) {
  const expectedQuery = buildExpectedQuery({ domain, facematch })
  let queue = Promise.resolve()

  // The WASM verifier is heavy and its first run writes shared cache files, so
  // verifications run one at a time.
  function serialized(task) {
    const run = queue.then(task, task)
    queue = run.catch(() => {})
    return run
  }

  async function verifyProof({ proofs, queryResult }) {
    if (!looksLikeProofSubmission({ proofs, queryResult })) return { verified: false }

    let result
    try {
      // originalQuery is ours, never the client's.
      result = await serialized(() =>
        zkPassport.verify({ proofs, originalQuery: expectedQuery, queryResult, scope, writingDirectory: "/tmp/zkp" }),
      )
    } catch (error) {
      if (isInputError(error)) return { verified: false }
      throw error
    }
    if (!result.verified) return { verified: false }

    const fields = fieldsFromProof(disclosedBytesOf(proofs))
    if (!fields || !satisfiesConstraints(fields, expectedQuery)) return { verified: false }
    return { verified: true, fields }
  }

  return { verifyProof, expectedQuery }
}

module.exports = { createVerifier, looksLikeProofSubmission, fieldsFromProof, MAX_PROOFS, MRZ_LENGTH }
