const http = require("node:http")
const fs = require("node:fs")
const { loadConfig } = require("./config")
const { loadEncryptionKey, encryptText } = require("./pgp")
const { createVerifier, BusyError, ServiceUnavailableError } = require("./verify")
const { fieldsBlock, buildBundle } = require("./bundle")
const { setUpRegistry } = require("./registry")

// A real submission is a few hundred kilobytes of proofs; anything near this
// limit is not one. Identifiers and references are short human-readable IDs.
const MAX_BODY_BYTES = 2 * 1024 * 1024
const MAX_ID_LENGTH = 200

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    let tooLarge = false
    req.on("data", (chunk) => {
      if (tooLarge) return // keep draining so the 413 below can be delivered
      size += chunk.length
      if (size > MAX_BODY_BYTES) {
        tooLarge = true
        chunks.length = 0
        return
      }
      chunks.push(chunk)
    })
    req.on("end", () => {
      if (tooLarge) return reject(Object.assign(new Error("Body too large"), { status: 413 }))
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")))
      } catch {
        reject(Object.assign(new Error("Body is not JSON"), { status: 400 }))
      }
    })
    req.on("error", reject)
  })
}

function send(res, status, body) {
  const headers = { "content-type": "application/json" }
  if (status === 413) headers.connection = "close"
  res.writeHead(status, headers)
  res.end(JSON.stringify(body))
}

function shortString(value) {
  return typeof value === "string" && value.length <= MAX_ID_LENGTH ? value : null
}

// Builds the request handler from its parts so tests can supply fakes.
function createApp({ config, legalKey, verifier, registryClient, log = console.log }) {
  return async function handle(req, res) {
    if (req.method === "GET" && req.url === "/health") return send(res, 200, { status: "ok" })
    if (req.method !== "POST" || req.url !== "/verify") return send(res, 404, { error: "not_found" })

    const started = Date.now()
    let body
    try {
      body = await readJsonBody(req)
    } catch (error) {
      return send(res, error.status || 400, { error: "bad_request" })
    }
    const identifier = shortString(body?.identifier)
    const reference = shortString(body?.reference ?? "")
    if (!identifier || reference === null) return send(res, 400, { error: "bad_request" })

    try {
      const outcome = await verifier.verifyProof({ proofs: body.proofs, queryResult: body.queryResult })
      if (!outcome.verified) {
        log(`verify ${identifier}: not verified (${Date.now() - started} ms)`)
        return send(res, 200, { verified: false })
      }

      const verifiedAt = new Date()
      const block = fieldsBlock({ fields: outcome.fields, identifier, reference, verifiedAt, facematch: config.facematch })
      const bundle = await buildBundle({
        proofs: body.proofs,
        queryResult: body.queryResult,
        expectedQuery: verifier.expectedQuery,
        identifier,
        reference,
        verifiedAt,
        config,
        registryClient,
      })
      const [fieldsBlockArmored, bundleArmored] = await Promise.all([
        encryptText(legalKey, block),
        encryptText(legalKey, JSON.stringify(bundle, null, 2)),
      ])
      log(`verify ${identifier}: verified (${Date.now() - started} ms)`)
      return send(res, 200, { verified: true, fieldsBlockArmored, bundleArmored })
    } catch (error) {
      if (error instanceof BusyError) {
        log(`verify ${identifier}: busy`)
        return send(res, 503, { error: "busy" })
      }
      if (error instanceof ServiceUnavailableError) {
        log(`verify ${identifier}: upstream services unreachable${error.cause ? ` (${error.cause.name}: ${error.cause.message})` : ""}`)
        return send(res, 503, { error: "verification_unavailable" })
      }
      log(`verify ${identifier}: error ${error.name}: ${error.message}`)
      return send(res, 500, { error: "verification_error" })
    }
  }
}

async function main() {
  const config = loadConfig()
  fs.mkdirSync("/tmp/zkp", { recursive: true })
  const legalKey = await loadEncryptionKey(config.publicKeysJsPath, "legal")
  const registryClient = await setUpRegistry()
  const verifier = createVerifier({ ...config, checkCertificateRoot: registryClient.checkCertificateRoot })
  const server = http.createServer(createApp({ config, legalKey, verifier, registryClient }))
  server.listen(config.port, () => console.log(`verifier listening on ${config.port}, face match ${config.facematch}`))
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`verifier failed to start: ${error.message}`)
    process.exit(1)
  })
}

module.exports = { createApp, readJsonBody, MAX_BODY_BYTES }
