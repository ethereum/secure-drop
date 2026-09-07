const { test } = require("node:test")
const assert = require("node:assert/strict")
const { setUpRegistry } = require("../src/registry")

function fakeClient({ rootAnswer = true, rootDelayMs = 0 } = {}) {
  const calls = { manifest: 0, addresses: 0, roots: [] }
  return {
    calls,
    async isCertificateRootValid(root, timestamp) {
      calls.roots.push({ root, timestamp })
      await new Promise((r) => setTimeout(r, rootDelayMs))
      if (rootAnswer instanceof Error) throw rootAnswer
      return rootAnswer
    },
    async getCertificateRegistryAddress() { calls.addresses++; return "0xcert" },
    async getCircuitRegistryAddress() { calls.addresses++; return "0xcirc" },
    getRootRegistryAddress() { return "0xroot" },
    async getCircuitManifest(root, { version }) { calls.manifest++; if (version === "9.9.9") throw new Error("404"); return { version, root: "0xr", circuits: {} } },
  }
}

test("addresses resolve once and manifests are cached per version", async () => {
  const client = fakeClient()
  const registry = await setUpRegistry(client)
  assert.equal(client.calls.addresses, 2)
  assert.equal(await registry.getCertificateRegistryAddress(), "0xcert")
  assert.equal(await registry.getCircuitRegistryAddress(), "0xcirc")
  assert.equal(registry.getRootRegistryAddress(), "0xroot")
  assert.equal(client.calls.addresses, 2)

  const a = await registry.getCircuitManifest(undefined, { version: "1.0.0" })
  const b = await registry.getCircuitManifest(undefined, { version: "1.0.0" })
  await registry.getCircuitManifest(undefined, { version: "1.1.0" })
  assert.equal(a, b)
  assert.equal(client.calls.manifest, 2)

  await assert.rejects(registry.getCircuitManifest(undefined, { version: "9.9.9" }), /404/)
  await assert.rejects(registry.getCircuitManifest(undefined, { version: "9.9.9" }), /404/)
  assert.equal(client.calls.manifest, 4, "a failed fetch is not cached")
})

test("the root check passes through answers and errors", async () => {
  const client = fakeClient({ rootAnswer: false })
  const registry = await setUpRegistry(client)
  assert.equal(await registry.checkCertificateRoot("0xabc", 1700000000), false)
  assert.deepEqual(client.calls.roots, [{ root: "0xabc", timestamp: 1700000000 }])
  await assert.rejects((await setUpRegistry(fakeClient({ rootAnswer: new Error("rpc down") }))).checkCertificateRoot("0x1", 1), /rpc down/)
})
