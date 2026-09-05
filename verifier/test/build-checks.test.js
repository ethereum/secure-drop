const { test } = require("node:test")
const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")

// Guards against a future SDK bump or code change quietly reintroducing
// behaviour this service must never have: contacting zkPassport's hosted
// verifier, attaching a dashboard policy, or registering the SDK callback
// that verifies proofs on its own.

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

test("nothing references the hosted verifier", () => {
  const src = filesUnder(path.join(__dirname, "..", "src"), [".js"])
  const sdk = filesUnder(path.join(__dirname, "..", "node_modules", "@zkpassport"), [".js", ".cjs"])
  assert.deepEqual(filesContaining([...src, ...sdk], "verifier.zkpassport.id"), [])
})

test("sidecar never attaches a policy or registers onResult", () => {
  const src = filesUnder(path.join(__dirname, "..", "src"), [".js"])
  assert.deepEqual(filesContaining(src, ".policy("), [])
  assert.deepEqual(filesContaining(src, "onResult"), [])
})
