const { test } = require("node:test")
const assert = require("node:assert/strict")
const { setUpRegistry } = require("../src/registry")

function fakeClient({ cdnOk = true, rpcOk = true } = {}) {
  const calls = { manifest: 0, addresses: 0 }
  return {
    calls,
    async getCertificateRegistryAddress() { calls.addresses++; return "0xcert" },
    async getCircuitRegistryAddress() { calls.addresses++; return "0xcirc" },
    getRootRegistryAddress() { return "0xroot" },
    async getCircuitManifest(root, { version }) { calls.manifest++; if (version === "9.9.9") throw new Error("404"); return { version, root: "0xr", circuits: {} } },
    async getLatestCertificateRoot() { if (!rpcOk) throw new Error("rpc down"); return "0xcr" },
    async getLatestCircuitRoot() { if (!rpcOk) throw new Error("rpc down"); return "0xr" },
    getUrlForCircuitManifestByRoot: (root) => (cdnOk ? "data:application/json,{}" : "http://127.0.0.1:9/nothing"),
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

test("reachability needs both the RPC and the CDN", async () => {
  assert.equal(await (await setUpRegistry(fakeClient())).servicesReachable(), true)
  assert.equal(await (await setUpRegistry(fakeClient({ rpcOk: false }))).servicesReachable(), false)
  assert.equal(await (await setUpRegistry(fakeClient({ cdnOk: false }))).servicesReachable(), false)
})
