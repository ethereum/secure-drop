const { test } = require("node:test")
const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")

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
