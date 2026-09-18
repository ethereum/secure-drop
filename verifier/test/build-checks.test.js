const { test } = require("node:test")
const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const { DISCLOSED_FIELDS, SCOPE } = require("../src/query")

// Guards against a code change quietly reintroducing behaviour this service
// must never have: contacting zkPassport's hosted verifier, attaching a
// dashboard policy, or registering the SDK callback that verifies proofs on
// its own. The SDK itself contains the hosted-verifier code; the sidecar keeps
// it unreachable by passing verifierMode "local", which verify.test.js checks.

function filesUnder(dir, extensions) {
  const out = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) out.push(...filesUnder(full, extensions))
    else if (extensions.some((ext) => entry.name.endsWith(ext))) out.push(full)
  }
  return out
}

function filesContaining(files, needle) {
  return files.filter((file) => fs.readFileSync(file, "utf8").includes(needle))
}

const src = () => filesUnder(path.join(__dirname, "..", "src"), [".js"])
const appJs = path.join(__dirname, "..", "..", "static", "js", "app.js")

test("sidecar source never reaches for the hosted verifier", () => {
  assert.deepEqual(filesContaining(src(), "verifier.zkpassport.id"), [])
  assert.deepEqual(filesContaining(src(), "verifyWithVerifierApi"), [])
  assert.deepEqual(filesContaining(src(), 'verifierMode: "auto"'), [])
  assert.deepEqual(filesContaining(src(), 'verifierMode: "api"'), [])
})

test("neither the sidecar nor the browser code attaches a policy or registers onResult", () => {
  assert.deepEqual(filesContaining([...src(), appJs], ".policy("), [])
  assert.deepEqual(filesContaining([...src(), appJs], "onResult"), [])
})

// The browser builds the real request and the verifier rebuilds the one it
// expects, each from its own constants. If they drift, every proof is rejected
// as a bad proof with nothing pointing at the cause, so they are compared here.
function extract(source, pattern, what, file) {
  const match = source.match(pattern)
  assert.ok(match, `could not find ${what} in ${file}`)
  return match[1]
}

test("the browser builds the same request the verifier expects", () => {
  const source = fs.readFileSync(appJs, "utf8")
  const fieldsSource = extract(source, /const PASSPORT_FIELDS = (\[[^\]]*\]);/, "PASSPORT_FIELDS", appJs)
  let fields
  try {
    fields = JSON.parse(fieldsSource)
  } catch {
    assert.fail(`PASSPORT_FIELDS in ${appJs} must be a plain array of double-quoted strings, no comments or trailing commas`)
  }
  assert.deepEqual([...fields].sort(), [...DISCLOSED_FIELDS].sort())
  assert.equal(extract(source, /const PASSPORT_SCOPE = "([^"]*)";/, "PASSPORT_SCOPE", appJs), SCOPE)
  // The same two constraints query.js applies, guarded the same way.
  assert.match(source, /\n\t\tquery = query\.eq\("document_type", "passport"\);/)
  assert.match(source, /if \(section\.dataset\.facematch !== "off"\) \{\s*query = query\.facematch\(section\.dataset\.facematch\);\s*\}/)
})

test("the vendored browser SDK is the version the verifier runs", () => {
  const bundle = path.join(__dirname, "..", "..", "static", "js", "zkpassport-sdk.min.js")
  const banner = fs.readFileSync(bundle, "utf8").slice(0, 300)
  const vendored = extract(banner, /@zkpassport\/sdk (\S+),/, "the SDK version banner", bundle)
  const installed = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "node_modules", "@zkpassport", "sdk", "package.json"), "utf8")).version
  assert.equal(vendored, installed, "run `npm run build:browser` after changing the SDK version")
})
