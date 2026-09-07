const { RegistryClient } = require("@zkpassport/registry")

const ROOT_CHECK_TIMEOUT_MS = 10 * 1000

// Wraps the registry client for the bundle builder: the two contract
// addresses are resolved once at startup and the circuit manifest is cached
// per circuit version, so a submission that has already verified cannot fail
// on a repeated fetch. Also exposes the certificate root check the verifier
// uses to tell a bad proof from an RPC outage.
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

  // Wraps the on-chain root check with a deadline so a hung RPC cannot hold a
  // request open past the web app's own timeout.
  async function checkCertificateRoot(root, timestamp) {
    let timer
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("registry RPC timed out")), ROOT_CHECK_TIMEOUT_MS)
    })
    try {
      return await Promise.race([client.isCertificateRootValid(root, timestamp), deadline])
    } finally {
      clearTimeout(timer)
    }
  }

  return {
    getCircuitManifest,
    getCertificateRegistryAddress: async () => certificateRegistry,
    getCircuitRegistryAddress: async () => circuitRegistry,
    getRootRegistryAddress: () => client.getRootRegistryAddress(),
    checkCertificateRoot,
  }
}

module.exports = { setUpRegistry }
