var createHash = require('create-hash')
var secp256k1 = require('secp256k1')
var varuint = require('varuint-bitcoin')
var { pubKeyToAddress } = require('@cobo/crypto-address')

function sha256 (b) {
  return createHash('sha256').update(b).digest()
}
function hash256 (buffer) {
  return sha256(sha256(buffer))
}

function encodeSignature (signature, recovery, compressed) {
  if (compressed) recovery += 4
  return Buffer.concat([Buffer.alloc(1, recovery + 27), signature])
}

function decodeSignature (buffer) {
  if (buffer.length !== 65) throw new Error('Invalid signature length')

  var flagByte = buffer.readUInt8(0) - 27
  if (flagByte > 7) throw new Error('Invalid signature parameter')

  return {
    compressed: !!(flagByte & 4),
    recovery: flagByte & 3,
    signature: buffer.slice(1)
  }
}

function magicHash (message, messagePrefix) {
  messagePrefix = messagePrefix || '\u0018Bitcoin Signed Message:\n'
  if (!Buffer.isBuffer(messagePrefix)) messagePrefix = Buffer.from(messagePrefix, 'utf8')

  var messageVISize = varuint.encodingLength(message.length)
  var buffer = Buffer.allocUnsafe(messagePrefix.length + messageVISize + message.length)
  messagePrefix.copy(buffer, 0)
  varuint.encode(message.length, buffer, messagePrefix.length)
  buffer.write(message, messagePrefix.length + messageVISize)
  return hash256(buffer)
}

function sign (message, privateKey, compressed, messagePrefix) {
  var hash = magicHash(message, messagePrefix)
  var sigObj = secp256k1.sign(hash, privateKey)
  return encodeSignature(sigObj.signature, sigObj.recovery, compressed)
}

function verify (message, address, signature, messagePrefix) {
  if (!Buffer.isBuffer(signature)) signature = Buffer.from(signature, 'base64')

  var parsed = decodeSignature(signature)
  var hash = magicHash(message, messagePrefix)
  var publicKey = secp256k1.recover(hash, parsed.signature, parsed.recovery, parsed.compressed)
  var addressType = verifyAddressType(address)
  var actual = pubKeyToAddress(publicKey, 'bitcoin', addressType, parsed.compressed)

  return actual === address
}

function verifyAddressType (address) {
  if (address[0] === '1') {
    return 'BITCOIN_BASIC'
  }

  if (address[0] === '3') {
    return 'SEGWIT_P2SH'
  }

  if (address.slice(0, 3) === 'bc1') {
    return 'SEGWIT_BECH32'
  }
}

module.exports = {
  magicHash: magicHash,
  sign: sign,
  verify: verify
}
