const fs = require("node:fs")
const openpgp = require("openpgp")

// Pulls one recipient's armored public key out of static/js/public-keys.js,
// the same file the browser uses, so keys live in one place.
function readPublicKeyBlock(publicKeysJsPath, recipient) {
  const source = fs.readFileSync(publicKeysJsPath, "utf8")
  const pattern = new RegExp(
    `publicKeys\\['${recipient}'\\][^\`]*\`(-----BEGIN PGP PUBLIC KEY BLOCK-----[\\s\\S]*?-----END PGP PUBLIC KEY BLOCK-----)`,
  )
  const match = source.match(pattern)
  if (!match) {
    throw new Error(`No PGP public key for "${recipient}" in ${publicKeysJsPath}`)
  }
  return match[1]
}

// Loads a recipient's key and checks it can still be used to encrypt.
// Throws if the key is expired, revoked, or has no encryption subkey.
async function loadEncryptionKey(publicKeysJsPath, recipient) {
  const key = await openpgp.readKey({ armoredKey: readPublicKeyBlock(publicKeysJsPath, recipient) })
  await key.getEncryptionKey()
  return key
}

// Same call the browser makes in app.js: armored PGP message to one key.
async function encryptText(key, text) {
  const message = await openpgp.createMessage({ text })
  return openpgp.encrypt({ message, encryptionKeys: key })
}

module.exports = { readPublicKeyBlock, loadEncryptionKey, encryptText }
