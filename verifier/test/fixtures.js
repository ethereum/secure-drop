// Shared synthetic passport and proof set for the sidecar tests. Shaped like
// what the zkPassport app produces in default mode after a JSON round trip.
const { getNumberOfPublicInputs, getServiceScopeHash, getScopeHash } = require("@zkpassport/utils")

const settings = { domain: "secure-drop.ethereum.org", scope: "ef-onboarding", facematch: "strict", gitSha: "abc1234" }
const proofDate = new Date("2026-09-05T13:58:00Z")
const certificateRoot = 0xabc123n

// A passport's machine-readable zone for JANE ANN DOE, Irish, born 1990-05-17,
// expiring 2031-01-02. Line 2: docno(9) chk nat(3) dob(6) chk sex expiry(6) chk personal(14) chk composite.
function mrzBytes({ documentCode = "P<", name = "DOE<<JANE<ANN", birth = "900517", sex = "F", expiry = "310102" } = {}) {
  const line1 = (documentCode + "IRL" + name + "<".repeat(44)).slice(0, 44)
  const line2 = "P12345678" + "4" + "IRL" + birth + "3" + sex + expiry + "7" + "<".repeat(14) + "<" + "6"
  return Array.from(new TextEncoder().encode(line1 + line2))
}

// A proof string as the app produces it: hex, no 0x, public inputs first.
function synthProof(name, publicInputs = {}, extra = {}) {
  const field = (v) => BigInt(v).toString(16).padStart(64, "0")
  const count = getNumberOfPublicInputs(name)
  const inputs = Array.from({ length: count }, (_, i) => field(publicInputs[i] ?? 0)).join("")
  return { proof: inputs + "ab".repeat(64), name, version: "1.0.0", ...extra }
}

function sampleProofs({ disclosedBytes = mrzBytes(), discloseMask = Array(88).fill(1), facematch = "strict" } = {}) {
  const proofs = [
    synthProof("sig_check_dsc_tbs_1000_rsa_pkcs_2048_sha256", { 0: certificateRoot }),
    synthProof("sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256"),
    synthProof("data_check_integrity_sa_sha256_dg_sha256"),
    synthProof(
      "disclose_bytes",
      { 1: Math.floor(proofDate.getTime() / 1000), 2: getServiceScopeHash(settings.domain), 3: getScopeHash(settings.scope) },
      { committedInputs: { disclose_bytes: { discloseMask, disclosedBytes } } },
    ),
  ]
  if (facematch !== "off") {
    proofs.push(synthProof("facematch_ios_rk_ecdsa_ik_count_1_ik_ecdsa_p256_sha256", {}, { committedInputs: { facematch: { mode: facematch, environment: "production" } } }))
  }
  return JSON.parse(JSON.stringify(proofs))
}

// What the phone says it disclosed. Deliberately different from the proof
// bytes so the tests can show it is never what legal receives.
const clientResult = {
  fullname: { disclose: { result: "JANE ANN DOE\nNationality: GBR" } },
  birthdate: { disclose: { result: "1990-05-16T05:00:00.000Z" } },
  document_type: { disclose: { result: "passport" }, eq: { expected: "passport", result: true } },
}

const expectedFields = {
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
}

module.exports = { settings, proofDate, certificateRoot, mrzBytes, synthProof, sampleProofs, clientResult, expectedFields }
