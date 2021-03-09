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
import * as bp2 from '../lib/crypto-lite/bip39.js';

const bip39 = require('bip39-light');
//const SafeBuffer = require('safe-buffer');
//const Buffer_from=require('buffer-from')
//const pbkdf2 = require('pbkdf2');
//const createHmac = require('create-hmac');
// globalThis.Buffer=SafeBuffer.Buffer
// globalThis.BN=BN
// globalThis.bip39=bip39
// globalThis.pbkdf2=pbkdf2
// globalThis.createHmacPackage={createHmac:createHmac}
async function mainAsync(){
    let buf = bip39.mnemonicToSeed("finger enlist involve portion figure tragic velvet library slab ribbon pulse bike");
    let b2 = await bp2.mnemonicToSeedAsync("finger enlist involve portion figure tragic velvet library slab ribbon pulse bike".split(" "));
    //results.push(u8arr.toString());
    //results.push(u8arr.toString("base64"))
    console.log(buf.toString('hex'));
    console.log(Buffer.from(b2).toString('hex'));
}

mainAsync()