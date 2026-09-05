const openpgp = require("openpgp")

// Loads a recipient's key from static/js/public-keys.js, the same file and the
// same lookup the browser uses, and checks it can still be used to encrypt.
// Throws if the recipient is unknown or the key is expired, revoked, or has no
// encryption subkey.
async function loadEncryptionKey(publicKeysJsPath, recipient) {
  const publicKeys = require(publicKeysJsPath)
  const armoredKey = publicKeys[recipient]
  if (!armoredKey) {
    throw new Error(`No PGP public key for "${recipient}" in ${publicKeysJsPath}`)
  }
  const key = await openpgp.readKey({ armoredKey })
  await key.getEncryptionKey()
  return key
}

// Same call the browser makes in app.js: armored PGP message to one key.
async function encryptText(key, text) {
  const message = await openpgp.createMessage({ text })
  return openpgp.encrypt({ message, encryptionKeys: key })
}

module.exports = { loadEncryptionKey, encryptText }
