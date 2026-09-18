const { test } = require("node:test")
const assert = require("node:assert/strict")
const fs = require("node:fs")
const os = require("node:os")
const path = require("node:path")
const openpgp = require("openpgp")
const { loadEncryptionKey, encryptText } = require("../src/pgp")

const publicKeysJs = path.join(__dirname, "..", "..", "static", "js", "public-keys.js")

// Writes a public-keys.js lookalike containing one key, for cases the real file should not have to provide.
function writeKeysFile(recipient, armoredKey) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "pgp-test-")), "public-keys.js")
  fs.writeFileSync(file, `var publicKeys=[];\npublicKeys['${recipient}']=${JSON.stringify(armoredKey)};\nmodule.exports = publicKeys;\n`)
  return file
}

// Whatever key legal currently uses must load and be usable for encryption.
// The key itself changes over time, so its identity is deliberately not checked.
test("finds a usable legal key in public-keys.js", async () => {
  const key = await loadEncryptionKey(publicKeysJs, "legal")
  assert.match(key.getFingerprint(), /^[0-9a-f]{40}$/)
  const armored = await encryptText(key, "probe")
  assert.ok(armored.startsWith("-----BEGIN PGP MESSAGE-----"))
})

test("unknown recipient throws", async () => {
  await assert.rejects(loadEncryptionKey(publicKeysJs, "nobody"), /No PGP public key for "nobody"/)
})

test("a key that cannot encrypt is rejected at load", async () => {
  const { publicKey } = await openpgp.generateKey({
    type: "ecc",
    curve: "ed25519",
    userIDs: [{ name: "signing only" }],
    subkeys: [],
  })
  await assert.rejects(loadEncryptionKey(writeKeysFile("signer", publicKey), "signer"), /encryption/i)
})

test("encrypted text decrypts with the matching private key", async () => {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: "ecc",
    curve: "curve25519",
    userIDs: [{ name: "test" }],
    format: "object",
  })
  const armored = await encryptText(publicKey, "hello legal")
  assert.ok(armored.startsWith("-----BEGIN PGP MESSAGE-----"))
  assert.ok(!armored.includes("hello legal"))
  const { data } = await openpgp.decrypt({
    message: await openpgp.readMessage({ armoredMessage: armored }),
    decryptionKeys: privateKey,
  })
  assert.equal(data, "hello legal")
})
