import * as bp2 from "./lib/crypto-lite/bip39.js"
import * as nhd1 from "./lib/old/near-hd-key-old.js"
import * as nhd2 from "./lib/new/near-hd-key-async.js"

declare var bip39:any;
declare var result1:HTMLInputElement;
declare var result2:HTMLInputElement;
declare var result31:HTMLInputElement;
declare var result32:HTMLInputElement;
declare var result41:HTMLInputElement;
declare var result42:HTMLInputElement;

async function mainAsync(){
    console.log(bip39.mnemonicToSeed("correct horse battery staple"))

    // const u8arr = bip39.mnemonicToSeed("correct horse battery staple")
    // result1.value = u8arr.toString("base64")
    
    // const u8arr2 = await bp2.mnemonicToSeed("correct horse battery staple")
    // result2.value = u8arr2.toString("base64")
    
    let buf = bip39.mnemonicToSeed("finger enlist involve portion figure tragic velvet library slab ribbon pulse bike");
    let b2 = Buffer.from(await bp2.mnemonicToSeedAsync("finger enlist involve portion figure tragic velvet library slab ribbon pulse bike".split(" ")));
    //results.push(u8arr.toString());
    //results.push(u8arr.toString("base64"))
    console.log(buf.toString('hex'));
    console.log(b2.toString('hex'));

    result1.value = buf.toString('base64')
    result2.value = b2.toString('base64')
    
    // const u8arr2 = await bp2.mnemonicToSeed("correct horse battery staple")
    // result2.value = u8arr2.toString("base64")

    const words = await bp2.generateMnemonicAsync();
    console.log(JSON.stringify(words));
    buf = bip39.mnemonicToSeed(words.join(" "));
    
    let masterKey = await bp2.mnemonicToSeedAsync(words);
    b2 = Buffer.from(masterKey);

    console.log(buf.toString('hex'));
    console.log(b2.toString('hex'));

    let keys_orig = nhd1.getMasterKeyFromSeed(buf);
    let keys=Object.assign({},keys_orig)
    keys = nhd1.CKDPriv(keys,5);

    // const KEY_DERIVATION_PATH = "m/44'/397'/0'"
    // let keys = nhd1.derivePath(KEY_DERIVATION_PATH, buf.toString('hex'));
    result31.value= JSON.stringify(keys.key);
    result32.value = JSON.stringify(keys.chainCode);

    // let keys2 = await nhd2.derivePathAsync(KEY_DERIVATION_PATH,b2);
    let keys2=Object.assign({},keys_orig)
    keys2 = await nhd2.CKDPrivAsync(keys2,5);
    result41.value= JSON.stringify(keys2.key);
    result42.value = JSON.stringify(keys2.chainCode);

    console.log("---------------------------")

    const KEY_DERIVATION_PATH = "m/44'/397'/0'"
    keys = nhd1.derivePath(KEY_DERIVATION_PATH, buf.toString('hex'));
    keys2 = await nhd2.derivePathAsync(KEY_DERIVATION_PATH, buf);

    console.log("---------------------------")
    console.log("old:",JSON.stringify(keys))
    console.log("new:",JSON.stringify(keys2))

}

mainAsync()