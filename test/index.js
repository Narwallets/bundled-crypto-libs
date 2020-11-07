

console.log(bip39.mnemonicToSeed("correct horse battery staple"))

const u8arr = bip39.mnemonicToSeed("correct horse battery staple")

result.value = u8arr.toString("base64")