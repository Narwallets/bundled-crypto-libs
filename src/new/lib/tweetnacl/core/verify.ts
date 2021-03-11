
function vn(x: Uint8Array, xi: number, y: Uint8Array, yi: number, n: number): number {
    let i, d = 0;

    for (i = 0; i < n; i++) d |= x[xi + i] ^ y[yi + i];

    return (1 & ((d - 1) >>> 8)) - 1;
}

export function _verify_16(x: Uint8Array, xi: number, y: Uint8Array, yi: number): number {
    return vn(x, xi, y, yi, 16);
}

export function _verify_32(x: Uint8Array, xi: number, y: Uint8Array, yi: number): number {
    return vn(x, xi, y, yi, 32);
}

export function verify(x: Uint8Array, y: Uint8Array): boolean {

    // Zero length arguments are considered not equal
    return x.length > 0 && y.length > 0 &&
        x.length == y.length &&
        vn(x, 0, y, 0, x.length) == 0;
}
