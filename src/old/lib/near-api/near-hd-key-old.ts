import {sign_keyPair_fromSeed} from "../tweetnacl/sign.js"

import type createHmacNamespace from "../bundled-types/create-hmac.js"
declare var createHmacPackage:typeof createHmacNamespace
const createHmac = createHmacPackage.createHmac

//import {sha512Async} from "../crypto-lite/crypto-primitives-browser.js"

declare type Keys = {
    key: Buffer;
    chainCode: Buffer;
};

const ED25519_CURVE = 'ed25519 seed';
const HARDENED_OFFSET = 0x80000000;


//utils------------
const pathRegex: RegExp = new RegExp("^m(\\/[0-9]+')+$");
function replaceDerive(val: string):string{
    return val.replace("'", '')
};
//------------

export function getMasterKeyFromSeed(seed: string): Keys {
    const hmac = createHmac('sha512', ED25519_CURVE);
    const I = hmac.update(Buffer.from(seed, 'hex')).digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
        key: IL,
        chainCode: IR,
    };
};

//@ts-ignore
export const CKDPriv = ({ key, chainCode }, index) => {
    
    console.log("old in",index,JSON.stringify({ key, chainCode }))

    const indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(index, 0);
    const data = Buffer.concat([Buffer.alloc(1, 0), key, indexBuffer]);
    const I = createHmac('sha512', chainCode)
        .update(data)
        .digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    const result = {
        key: IL,
        chainCode: IR,
    };
    console.log("old out",index,JSON.stringify(result))
    return result;

};

export function getPublicKey(privateKey: Buffer, withZeroByte: boolean=true): Buffer {
    const keyPair = sign_keyPair_fromSeed(privateKey);
    const signPk = keyPair.secretKey.subarray(32);
    const zero = Buffer.alloc(1, 0);
    return withZeroByte ?
        Buffer.concat([zero, Buffer.from(signPk)]) :
        Buffer.from(signPk);
};

export function isValidPath (path: string) : boolean {
    if (!pathRegex.test(path)) {
        return false;
    }
    for(let item of path.split('/').slice(1)){
        if (isNaN(Number(replaceDerive(item)))) return false;
    }
    return true;
    // return !path
    //     .split('/')
    //     .slice(1)
    //     .map(replaceDerive)
    //     .some(isNaN);
};

export function derivePath(path: string, seed: string): Keys {
    if (!isValidPath(path)) {
        throw new Error('Invalid derivation path');
    }
    const { key, chainCode } = getMasterKeyFromSeed(seed);
    const segments = path
        .split('/')
        .slice(1)
        .map(replaceDerive)
        .map(el => parseInt(el, 10));
    return segments.reduce((parentKeys, segment) => CKDPriv(parentKeys, segment + HARDENED_OFFSET), { key, chainCode });
};
