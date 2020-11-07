const bip39=require('bip39-light')
const BN=require('bn.js')
const SafeBuffer=require('safe-buffer')
//const Buffer_from=require('buffer-from')
const pbkdf2 = require('pbkdf2')
const createHmac = require('create-hmac')

globalThis.Buffer=SafeBuffer.Buffer
globalThis.BN=BN
globalThis.bip39=bip39
globalThis.pbkdf2=pbkdf2
globalThis.createHmacPackage={createHmac:createHmac}