const { ZKPassport } = require("@zkpassport/sdk")

// Every field the zkPassport SDK can disclose.
const DISCLOSED_FIELDS = [
  "fullname",
  "firstname",
  "lastname",
  "birthdate",
  "nationality",
  "gender",
  "document_number",
  "expiry_date",
  "issuing_country",
  "document_type",
]

const FACEMATCH_MODES = ["strict", "regular", "off"]

// Builds the query every applicant proof must match. The browser builds the
// same query; the sidecar never trusts the one the client sends.
function buildExpectedQuery({ domain, facematch }) {
  if (!FACEMATCH_MODES.includes(facematch)) {
    throw new Error(`ZKPASSPORT_FACEMATCH must be one of ${FACEMATCH_MODES.join(", ")}, got "${facematch}"`)
  }
  let builder = new ZKPassport(domain).createQuery()
  for (const field of DISCLOSED_FIELDS) {
    builder = builder.disclose(field)
  }
  builder = builder.eq("document_type", "passport")
  if (facematch !== "off") {
    builder = builder.facematch(facematch)
  }
  return builder.done().query
}

module.exports = { buildExpectedQuery, DISCLOSED_FIELDS, FACEMATCH_MODES }
