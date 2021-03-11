import * as bip39New from "./new/lib/crypto-lite/bip39.js"

import * as clite from "./new/lib/crypto-lite/crypto-primitives-browser.js"
import {Uint8ArrayFromString, encodeBase64, decodeBase64, stringFromUint8Array} from "./new/lib/crypto-lite/encode.js"

import * as nhd1 from "./old/lib/near-api/near-hd-key-old.js"
import * as nhd2 from "./new/lib/near-api/near-hd-key-async.js"

//import * as naclFast from "./old/util/nacl-fast/nacl-fast.js"
import * as naclFast from "./new/lib/naclfast-secret-box/nacl-fast.js"
import * as naclUtil from "./old/util/nacl-fast/nacl-util.js";
import * as old_sha256 from "./old/lib/sha256.js";

import * as naclnew from "./new/lib/tweetnacl/sign.js"

declare var bip39:any;
declare var result1:HTMLInputElement;
declare var result2:HTMLInputElement;
declare var result31:HTMLInputElement;
declare var result32:HTMLInputElement;
declare var result41:HTMLInputElement;
declare var result42:HTMLInputElement;


async function test_nacl_fast_sha256_encode_base_64(){
    
    const password ="slkdjfslkdfjlsdkjflewjiAAAA#ºsdfgsñññw"
    
    result1.value = naclUtil.encodeBase64(old_sha256.hash(naclUtil.decodeUTF8(password)));
    
    result2.value = encodeBase64(new Uint8Array(await clite.sha256Async(Uint8ArrayFromString(password))));


}

function decryptIntoJson_OLD(hashedPassBase64:string, encryptedMsg:string):any {

    if (!encryptedMsg) throw new Error("encryptedState is empty");
  
    const keyPair = naclFast.sign_keyPair_fromSeed(decodeBase64(hashedPassBase64));
    const keyUint8Array = keyPair.publicKey;
  
    const messageWithNonceAsUint8Array = decodeBase64(encryptedMsg);
    const nonce = messageWithNonceAsUint8Array.slice(0, naclFast.secretbox_nonceLength);
    const message = messageWithNonceAsUint8Array.slice(
      naclFast.secretbox_nonceLength,
      encryptedMsg.length
    );
  
    const decrypted = naclFast.secretbox_open(message, nonce, keyUint8Array);
  
    if (decrypted == null || !decrypted) throw Error("INVALID_USER_OR_PASS");
  
    const base64DecryptedMessage = stringFromUint8Array(decrypted as Uint8Array);
    return JSON.parse(base64DecryptedMessage);
  }
  
const encryptedState = "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"
const decryptedState = '{"dataVersion":"0.1","hashedPass":"73l8gRjwLftklgfdXT+MdiMEjJwGPVMsyVxe16iYpk8=","initialNetworkName":"mainnet","autoUnlockSeconds":3000,"advancedMode":true,"accounts":{"mainnet":{"luciotato.near":{"order":1,"type":"acc","note":"","lastBalance":3.0415000000000134,"stakingPool":"openshards.poolv1.near","staked":7213.3869,"unStaked":0,"rewards":68.2487000000001,"stakingPoolPct":5,"lockedOther":0,"privateKey":"ed25519:5QrcVnD9eQdw8V3yrXStuyiHDKUDsqjWQ8CfS3vizgP89jfSg3hQoQ3tGjoFa5p9ReamZG8aZfnNA8RLj4cky38W","unstaked":0},"f481fe97dddaa46fcede6ea5d24e685066b123b5.lockup.near":{"order":3,"type":"lock.c","note":"mistake","lastBalance":36.0025,"stakingPool":"openshards.poolv1.near","staked":5071.107,"unStaked":0,"rewards":107.10699999999997,"stakingPoolPct":1,"ownerId":"luciotato.near","lockedOther":0,"unstaked":0},"developer.near":{"order":3,"type":"acc","note":"","lastBalance":3.994299999999999,"staked":0,"unStaked":0,"rewards":0,"privateKey":"ed25519:2dyYDA2ZQ6RA21Zbgo8vYLDVeSWZGbgNoZDC2ToU3FtpwFUWkqudhMMKZmhYDSUDy133vSnMSURBLgR3BAaDqU96","lockedOther":0},"5845b1dca764a660e1fda59eda6f8a78c501e165ce34f0bf62ddee69a945d6a9":{"order":3,"type":"acc","note":"trust.w","lastBalance":0.9839,"staked":0,"unStaked":0,"rewards":0,"lockedOther":0,"unstaked":0,"privateKey":"ed25519:3mtLKTxVSdpHWMiwKFM5mfbMjU1rZwvvsJ66PGeT5UVuCMbfWMa5NfPusVSbfCswH9q7T15UtLy2doCv4oRW36sY"},"2b573f0dd26c4376025fc8d10b31e2a6d104e19c.lockup.near":{"order":3,"type":"lock.c","note":"","lastBalance":37.2517,"stakingPool":"zavodil.poolv1.near","staked":1637.0001,"unStaked":0,"rewards":77.00009999999997,"stakingPoolPct":1,"ownerId":"5845b1dca764a660e1fda59eda6f8a78c501e165ce34f0bf62ddee69a945d6a9","lockedOther":0,"unstaked":0},"laura-wulff.near":{"order":7,"type":"acc","note":"","lastBalance":2.4953,"staked":0,"unstaked":0,"rewards":0,"lockedOther":0,"privateKey":"ed25519:57KsnTGapGGntMsWY2xbk82c55Ta83VWpjRM7EHo3xoabcGaaxDLWLJmdM4BtjTbYM2pVgTMY8g6bMXeUMdgtY51"},"narwallets.near":{"order":7,"type":"acc","note":"","lastBalance":3.0476,"staked":0,"unstaked":0,"rewards":0,"lockedOther":0,"privateKey":"ed25519:5HzQpAWH6wWTmC6ZJBVS6VNCUkzmPhZ5karrnRMK1hcKtBkvob1sZymj6cHb9fgr6ASm9rMFDF3mALKhNTTav2aR"},"532b799c2ae223941a54d377ee87c2ac7ba79d15.lockup.near":{"order":8,"type":"lock.c","note":"","lastBalance":36.0014,"staked":261.9999,"unstaked":0,"rewards":-0.00009999999997489795,"lockedOther":217.1404,"ownerId":"narwallets.near","stakingPool":"zavodil.poolv1.near","stakingPoolPct":1},"art-merchant.near":{"order":9,"type":"acc","note":"","lastBalance":25.988799999999998,"staked":332.7532,"unstaked":0,"rewards":0,"lockedOther":0,"privateKey":"ed25519:4yYMBBe6t7vpecSN9zVLjV2SwS474y42EjPkBnzVzKMMbQiMw1PsNfLg4dvNemAXQvWDrQ7fSvTCH3iQo92RCLYS","stakingPool":"zavodil.poolv1.near","stakingPoolPct":1}},"guildnet":{"staking.guildnet":{"order":5,"type":"acc","note":"","lastBalance":95100.0654,"staked":0,"unstaked":104025.2368,"rewards":0,"lockedOther":0,"privateKey":"ed25519:3xSZ3DkBWBYookYy3yRSnc9ph74i6tDEVCvN6hPw1imcDSwbdFLsoq9VWkiB7AwfCKk2GKA7Qgd4TcPimTE3Du5A","stakingPool":"staking-pool-4.guildnet","stakingPoolPct":7},"lucky.stake.guildnet":{"order":5,"type":"acc","note":"","lastBalance":0.0015,"staked":0,"unstaked":0,"rewards":0,"lockedOther":0},"luciotato.guildnet":{"order":1,"type":"acc","note":"","lastBalance":339086.8758,"staked":0,"unstaked":0,"rewards":0,"lockedOther":0,"stakingPool":"staking-pool-5.guildnet","stakingPoolPct":7,"privateKey":"ed25519:3xjxckPZ8TWSRW6Cqq75mc2TZqJRuw9JaNCxUrAoBMF7PmbUZ62vhzSVv1hwBhxQqVHZqvfsKnaE2k39DLkd9jXk"},"90027aec7944e8e70cf1f86fa255ac18866bb043.lockup.guildnet":{"order":5,"type":"lock.c","note":"","lastBalance":35.9985,"staked":107.186,"unstaked":0,"rewards":97.52600000000001,"lockedOther":41.2372,"ownerId":"luciotato.guildnet","stakingPool":"31337.stake.guildnet","stakingPoolPct":10},"staking-pool-2.guildnet":{"order":4,"type":"acc","note":"","lastBalance":15.0004,"staked":0,"unstaked":0,"rewards":0,"lockedOther":0,"privateKey":"ed25519:37ALLGVd8vkG7Jj5dhG1dZ9ALCztC5cK3GZcCugE3RheJY9CyoSHzDNWumD6V9tr1YDVvzFXNLpTTJE5AnmRxesL"},"luciotato2.guildnet":{"order":5,"type":"acc","note":"","lastBalance":712.4926,"staked":0,"unstaked":0,"rewards":0,"lockedOther":0,"privateKey":"ed25519:2hvjvoJ9SWGsMvYSd8k2mcX4VtUmqRCUEMUpi86QUuk5K47tTFTo16QB5D7PBJjtbRXkNRqqQKiMk4XfSKcd51Vz"},"testuser.guildnet":{"order":2,"type":"acc","note":"","lastBalance":89806.9903,"staked":39275.9297,"unstaked":0,"rewards":0,"lockedOther":0,"privateKey":"ed25519:4uJKExDHZ59WwnhvtD1FWAS6Dn9TwubzqTiU2CpiTLnE5vBRa8KsUgHQG8HTprtdTDt4LdyUM2J1gNSKtnpSM3vn","stakingPool":"staking-pool-2.guildnet","stakingPoolPct":7},"pools.guildnet":{"order":5,"type":"acc","note":"","lastBalance":13629.9859,"staked":0,"unstaked":101326.1351,"rewards":185.19710000000487,"lockedOther":0,"privateKey":"ed25519:34BRUGr4Lvky3aEpqXNJ2m6eLfrwQPfK6QBvE7ecHybev7hC52DCXGu4eZxnR5SC2Qgj2gyLe6jB3RAahyJEEMdr","stakingPool":"staking-pool-2.guildnet","stakingPoolPct":7},"staking-pool-3.guildnet":{"order":4,"type":"acc","note":"","lastBalance":5.0004,"staked":0,"unstaked":0,"rewards":0,"lockedOther":0,"privateKey":"ed25519:ey9Gi3DtvUB1K9oLdUiBNmnnHWEJGRcjF5A2D7naWC1kg9XHkMu5NdNHHyy3zZy5qPcwTTNd9yZ4KHSAtoMdMpU"},"w4.guildnet":{"order":3,"type":"acc","note":"","lastBalance":1379.9907,"staked":0,"unstaked":265389.8714,"rewards":485.06180000002496,"lockedOther":0,"privateKey":"ed25519:56eCGbGWtfJ32YmL4sFW7Xxt83RwYCmN2Mfb1FRj7qtEpSnb1nM9A1c3n61GzBDaBjeYU6zNrwCFZmkL41TqgzAg","stakingPool":"staking-pool-4.guildnet","stakingPoolPct":7},"staking-pool-5.guildnet":{"order":4,"type":"acc","note":"","lastBalance":509.9999,"staked":0,"unstaked":0,"rewards":0,"lockedOther":0,"privateKey":"ed25519:49jzbKWwuRZPnHZBDPZZNMcYcznL4wW8phnMMRQHiz32kyD1GDB5gsuRJuQFmhTCz4JdxVn6HYMtbabnSzeBHfdP"},"stkuser.guildnet":{"order":3,"type":"acc","note":"","lastBalance":34509.9886,"staked":36633.3328,"unstaked":0,"rewards":1633.332899999994,"lockedOther":0,"privateKey":"ed25519:3un83qUwreRvF669EoGgPE82qzzQ3K8oB7jJbxBZ41V9tqY3QNBcBj8JSgT781w8983tJXnmJKXnfZ8gZEuuL8Te","stakingPool":"staking-pool-5.guildnet","stakingPoolPct":7},"diversifying.pools.guildnet":{"order":13,"type":"acc","note":"","lastBalance":29002.9996,"staked":0,"unstaked":0,"rewards":0,"lockedOther":0}},"testnet":{"laura-wulff.testnet":{"order":3,"type":"acc","note":"","lastBalance":347.4998,"staked":0,"unstaked":0,"rewards":0,"lockedOther":0},"lucio.testnet":{"order":1,"type":"acc","note":"","lastBalance":99658.4812,"staked":502944.2009,"unstaked":4750,"rewards":0,"lockedOther":0,"privateKey":"ed25519:WVBbfuZ7HN8mWqDuFBYaro1yiwBj4oENQb48JFkM6mUYZG9LUJZQqRJGHQPN1MxXMJmtvCuEamfb1k4Cdrp4srM","stakingPool":"lunanova.pool.f863973.m0","stakingPoolPct":10},"274e981786efcabbe87794f20348c1b2af6e7963.lockupy.testnet":{"order":2,"type":"lock.c","note":"","lastBalance":99.9989,"staked":0,"unstaked":0,"rewards":0,"lockedOther":99.9805,"ownerId":"lucio.testnet","stakingPool":""},"meta.pool.testnet":{"order":3,"type":"acc","note":"","lastBalance":5047.547,"staked":0,"unstaked":0,"rewards":0,"lockedOther":0},"87b5008d2d1a7f7168c88e51f1082e01b1937e1fab89ff1b25c3b1ab61e8ddad":{"order":2,"type":"acc","note":"","lastBalance":0,"staked":0,"unstaked":0,"rewards":0,"lockedOther":0,"privateKey":"zJrZNh5fra1PDQuVgnPKby9GV41CbY4UDvyMzmJXsFSPpR8wegSgf1KUZZSDVLESxtUvRDZTU9pf71nnrrsbqzt"},"3c89ee89ba64a9f13fb2bf2d6c6baa3fc884b49d4e89bb09a0f5ded309b6bb19":{"order":2,"type":"acc","note":"","lastBalance":0,"staked":0,"unstaked":0,"rewards":0,"lockedOther":0,"privateKey":"4v2LspRcyrk3NdMcaNhbFBLtZjR9fsEEH7nMgnLiw8LbN3rXRLQLd72hz5Diano8Bi1MimeaYbb18GYwbvefuQuv"}}}}'

// async function test_decrypt(){
//     const password ="12345678"

//     let SecureState = JSON.parse(decryptedState)
    
//     let result = decryptIntoJson_OLD(SecureState.hashedPass,encryptedState)
//     //console.log(result)

//     console.log("naclfast decrypt OK?",JSON.stringify(result)==decryptedState)
// }

  async function test_tweetnacl_secret_box(){
    
    const password ="12345678"

    let SecureState = JSON.parse(decryptedState)
    
    const keyPair = naclnew.sign_keyPair_fromSeed(decodeBase64(SecureState.hashedPass));
    const keyUint8Array = keyPair.publicKey;
  
    //const nonce = naclFast.randomBytes(naclFast.secretbox_nonceLength);
    const nonce = decodeBase64("g9FwoZ3At4DEmsJNI8IWxINs0e/UtqTx")

    const messageUint8 = Uint8ArrayFromString(JSON.stringify(SecureState));
    const box = naclFast.secretbox(messageUint8, nonce, keyUint8Array);
  
    const fullMessage = new Uint8Array(nonce.length + box.length);
    fullMessage.set(nonce);
    fullMessage.set(box, nonce.length);
  
    const base64FullMessage = encodeBase64(fullMessage);
  
    result1.value = base64FullMessage
    result2.value = encryptedState

    console.log("naclfast encrypt OK?",base64FullMessage==encryptedState)

    let result = decryptIntoJson_OLD(SecureState.hashedPass,base64FullMessage)
    //console.log(result)

    console.log("naclfast decrypt OK?",JSON.stringify(result)==decryptedState)

}


async function test_tweetnacl_secret_box2(){
    

    let SecureState = JSON.parse(decryptedState)
    
    const keyPair = naclFast.sign_keyPair_fromSeed(decodeBase64(SecureState.hashedPass));
    const keyUint8Array = keyPair.publicKey;
  
    //const nonce = naclFast.randomBytes(naclFast.secretbox_nonceLength);
    const nonce = decodeBase64("g9FwoZ3At4DEmsJNI8IWxINs0e/UtqTx")

    const messageUint8 = Uint8ArrayFromString(JSON.stringify(SecureState));
    const box = naclFast.secretbox(messageUint8, nonce, keyUint8Array);
  
    const fullMessage = new Uint8Array(nonce.length + box.length);
    fullMessage.set(nonce);
    fullMessage.set(box, nonce.length);
  
    const base64FullMessage = encodeBase64(fullMessage);
  
    result1.value = base64FullMessage
    result2.value = encryptedState

    console.log("naclfast encrypt OK?",base64FullMessage==encryptedState)

    let result = decryptIntoJson_OLD(SecureState.hashedPass,base64FullMessage)
    //console.log(result)

    console.log("naclfast decrypt OK?",JSON.stringify(result)==decryptedState)

}

async function test_bip39(){
    console.log(bip39.mnemonicToSeed("correct horse battery staple"))

    // const u8arr = bip39.mnemonicToSeed("correct horse battery staple")
    // result1.value = u8arr.toString("base64")
    
    // const u8arr2 = await bp2.mnemonicToSeed("correct horse battery staple")
    // result2.value = u8arr2.toString("base64")
    
    let buf = bip39.mnemonicToSeed("finger enlist involve portion figure tragic velvet library slab ribbon pulse bike");
    let b2 = Buffer.from(await bip39New.mnemonicToSeedAsync("finger enlist involve portion figure tragic velvet library slab ribbon pulse bike".split(" ")));
    //results.push(u8arr.toString());
    //results.push(u8arr.toString("base64"))
    console.log(buf.toString('hex'));
    console.log(b2.toString('hex'));

    result1.value = buf.toString('base64')
    result2.value = b2.toString('base64')
    
    // const u8arr2 = await bp2.mnemonicToSeed("correct horse battery staple")
    // result2.value = u8arr2.toString("base64")

    const words = await bip39New.generateMnemonicAsync();
    console.log(JSON.stringify(words));
    buf = bip39.mnemonicToSeed(words.join(" "));
    
    let masterKey = await bip39New.mnemonicToSeedAsync(words);
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

async function test_near_hd_key(){

    let buf = bip39.mnemonicToSeed("finger enlist involve portion figure tragic velvet library slab ribbon pulse bike");
    let b2 = Buffer.from(await bip39New.mnemonicToSeedAsync("finger enlist involve portion figure tragic velvet library slab ribbon pulse bike".split(" ")));

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

//test_bip39()
//test_near_hd_key()
//test_nacl_fast_sha256_encode_base_64()

//test_decrypt()
test_tweetnacl_secret_box()