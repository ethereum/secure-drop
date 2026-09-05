const { test } = require("node:test")
const assert = require("node:assert/strict")
const path = require("node:path")
const openpgp = require("openpgp")
const { readPublicKeyBlock, loadEncryptionKey, encryptText } = require("../src/pgp")

const publicKeysJs = path.join(__dirname, "..", "..", "static", "js", "public-keys.js")

test("finds the legal key in public-keys.js", async () => {
  const block = readPublicKeyBlock(publicKeysJs, "legal")
  assert.ok(block.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
  assert.ok(block.endsWith("-----END PGP PUBLIC KEY BLOCK-----"))
  const key = await loadEncryptionKey(publicKeysJs, "legal")
  assert.equal(key.getFingerprint().toUpperCase(), "A6E7EF2FE95F127BC842258F5EEF80BE525AF017")
})

test("unknown recipient throws", () => {
  assert.throws(() => readPublicKeyBlock(publicKeysJs, "nobody"), /No PGP public key for "nobody"/)
})

test("a key that cannot encrypt is rejected at load", async () => {
  // The security key expired on 2026-02-22; openpgp refuses to encrypt to it.
  await assert.rejects(loadEncryptionKey(publicKeysJs, "security"), /expired/i)
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
