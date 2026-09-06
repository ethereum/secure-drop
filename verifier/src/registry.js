const { RegistryClient } = require("@zkpassport/registry")

// Wraps the registry client for the bundle builder: the two contract
// addresses are resolved once at startup and the circuit manifest is cached
// per circuit version, so a submission that has already verified cannot fail
// on a repeated fetch. Also answers whether the registry RPC and circuits CDN
// are reachable, which the verifier uses to tell a bad proof from an outage.
async function setUpRegistry(client = new RegistryClient({ chainId: 1 })) {
  const [certificateRegistry, circuitRegistry] = await Promise.all([
    client.getCertificateRegistryAddress(),
    client.getCircuitRegistryAddress(),
  ])
  const manifests = new Map()

  async function getCircuitManifest(root, { version } = {}) {
    if (!manifests.has(version)) {
      manifests.set(version, client.getCircuitManifest(root, { version }).catch((error) => {
        manifests.delete(version)
        throw error
      }))
    }
    return manifests.get(version)
  }

  async function cdnReachable() {
    const response = await fetch(client.getUrlForCircuitManifestByRoot(await client.getLatestCircuitRoot()), { method: "HEAD" })
    if (!response.ok) throw new Error(`circuits CDN answered ${response.status}`)
  }

  async function servicesReachable() {
    const probes = await Promise.allSettled([client.getLatestCertificateRoot(), cdnReachable()])
    return probes.every((p) => p.status === "fulfilled")
  }

  return {
    getCircuitManifest,
    getCertificateRegistryAddress: async () => certificateRegistry,
    getCircuitRegistryAddress: async () => circuitRegistry,
    getRootRegistryAddress: () => client.getRootRegistryAddress(),
    servicesReachable,
  }
}

module.exports = { setUpRegistry }
