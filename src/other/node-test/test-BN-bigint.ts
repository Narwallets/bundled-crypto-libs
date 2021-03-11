/*
const bip39=require('bip39-light')
const BN=require('bn.js')
const SafeBuffer=require('safe-buffer')
//const Buffer_from=require('buffer-from')
const pbkdf2 = require('pbkdf2')
const createHmac = require('create-hmac')

// globalThis.Buffer=SafeBuffer.Buffer
// globalThis.BN=BN
// globalThis.bip39=bip39
// globalThis.pbkdf2=pbkdf2
// globalThis.createHmacPackage={createHmac:createHmac}

let results=[]
results.push(BN("10000000").toString())
let u8arr:Uint8Array=bip39.mnemonicToSeed("correct horse battery staple")
results.push(u8arr.toString())
//results.push(u8arr.toString("base64"))

console.log(JSON.stringify(results))
*/

//const bip39 = require('bip39-light');
import * as bint from "../../new/lib/crypto-lite/bigint-buffer.js"
const BN = require('bn.js');
//const SafeBuffer = require('safe-buffer');
//const Buffer_from=require('buffer-from')
//const pbkdf2 = require('pbkdf2');
//const createHmac = require('create-hmac');
// globalThis.Buffer=SafeBuffer.Buffer
// globalThis.BN=BN
// globalThis.bip39=bip39
// globalThis.pbkdf2=pbkdf2
// globalThis.createHmacPackage={createHmac:createHmac}
let results = [];
let b=new BN(2+4*256+8*65536);
let b2=BigInt(2+4*256+8*65536);
b2=b2*b2;
b2=b2*b2;
b=new BN(b2.toString());
results.push(b.toString());
results.push(b2.toString());

results.push(b.toArray('le',16))
results.push([...bint.toBufferLE(b2,16)])
//let u8arr = bip39.mnemonicToSeed("correct horse battery staple");
//results.push(u8arr.toString());
//results.push(u8arr.toString("base64"))
console.log(JSON.stringify(results));
