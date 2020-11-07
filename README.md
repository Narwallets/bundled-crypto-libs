## Narwallets chrome extension support crypt libs bundle

This project just builds a bundle to use with https://github.com/Narwallets/narwallets-extension.git


TO DO:

* Convers/find typescript version of one of the libraries
* Remove form the bundle until it dissapears

Currently included libs:

```
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
```
