const { ZKPassport } = require("@zkpassport/sdk")
const { DisclosedData } = require("@zkpassport/utils")
const { buildExpectedQuery, DISCLOSED_FIELDS } = require("./query")

const MRZ_LENGTH = 88 // two 44-character lines of a passport's machine-readable zone
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
  { role: "facematch", matches: (name) => name === "facematch" },
]

class BusyError extends Error {
  constructor() {
    super("Verifier is busy")
    this.name = "BusyError"
  }
}

function isBytes(value, length, allowed) {
  return Array.isArray(value) && value.length === length && value.every((b) => Number.isInteger(b) && allowed(b))
}

function wellFormedProof(p) {
  if (!p || typeof p !== "object") return false
  if (typeof p.proof !== "string" || p.proof.length === 0 || p.proof.length > MAX_PROOF_HEX || !/^[0-9a-f]+$/.test(p.proof)) return false
  if (typeof p.name !== "string" || typeof p.version !== "string" || !/^\d+\.\d+\.\d+$/.test(p.version)) return false
  // Our request never produces these. Their names make the SDK verify
  // on-chain through a third-party RPC instead of locally.
  return !p.name.includes("evm")
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

// The disclosure proof must commit to a full, unmasked passport zone: our
// query discloses every field, so any masked byte means a tampered prover.
function disclosedBytesOf(disclosureProof) {
  const inputs = disclosureProof.committedInputs?.disclose_bytes
  if (!inputs || !isBytes(inputs.disclosedBytes, MRZ_LENGTH, (b) => b >= 0 && b <= 255)) return null
  if (!isBytes(inputs.discloseMask, MRZ_LENGTH, (b) => b === 1)) return null
  return inputs.disclosedBytes
}

function looksLikeProofSubmission({ proofs, queryResult }, facematch) {
  const roles = classifyProofs(proofs, facematch !== "off")
  if (!roles || disclosedBytesOf(roles.disclosure) === null) return false
  if (roles.facematch && roles.facematch.committedInputs?.facematch?.mode !== facematch) return false
  if (queryResult === null || typeof queryResult !== "object") return false
  return JSON.stringify(queryResult).length <= MAX_QUERY_RESULT_JSON
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
  for (const name of DISCLOSED_FIELDS) {
    if (typeof fields[name] !== "string" || fields[name] === "") return null
  }
  return fields
}

// Every eq in the expected query must hold for the derived fields.
function satisfiesConstraints(fields, expectedQuery) {
  return Object.entries(expectedQuery).every(([name, rule]) => rule?.eq === undefined || fields[name] === rule.eq)
}

function createVerifier({ domain, scope, facematch, zkPassport = new ZKPassport(domain) }) {
  const expectedQuery = buildExpectedQuery({ domain, facematch })
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

  // Resolves { verified: false } for anything malformed or unproven. Throws
  // BusyError when the line is full, and rethrows SDK errors, which after the
  // shape checks above can only mean the service itself has a problem.
  async function verifyProof({ proofs, queryResult }) {
    if (!looksLikeProofSubmission({ proofs, queryResult }, facematch)) return { verified: false }

    // originalQuery is ours, never the client's.
    const result = await serialized(() =>
      zkPassport.verify({ proofs, originalQuery: expectedQuery, queryResult, scope, writingDirectory: "/tmp/zkp" }),
    )
    if (!result.verified) return { verified: false }

    const roles = classifyProofs(proofs, facematch !== "off")
    const fields = fieldsFromProof(disclosedBytesOf(roles.disclosure))
    if (!fields || !satisfiesConstraints(fields, expectedQuery)) return { verified: false }
    return { verified: true, fields }
  }

  return { verifyProof, expectedQuery }
}

module.exports = { createVerifier, classifyProofs, looksLikeProofSubmission, fieldsFromProof, BusyError, MRZ_LENGTH, MAX_QUEUE }
