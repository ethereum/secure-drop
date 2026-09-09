const { ZKPassport } = require("@zkpassport/sdk")

// The label baked into every proof alongside the domain. Fixed in code because
// its only job is to tell the verifier "this proof was made for this flow".
// The browser's copy is PASSPORT_SCOPE in static/js/app.js and must match.
const SCOPE = "ef-onboarding"

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

// Builds the query the sidecar passes to the SDK as the original query. The
// browser builds the same one. The face match mode has already been validated
// by loadConfig.
function buildExpectedQuery({ domain, facematch }) {
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

module.exports = { buildExpectedQuery, DISCLOSED_FIELDS, SCOPE }
