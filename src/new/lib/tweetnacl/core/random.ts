const QUOTE = 1 << 16;

export function _randomBytes(x: Uint8Array, n: number) {
    for (let i = 0; i < n; i += QUOTE) {
        crypto.getRandomValues(x.subarray(i, i + Math.min(n - i, QUOTE)));
    }
}

export function randomBytes(n: number): Uint8Array {
    const b = new Uint8Array(n);
    _randomBytes(b, n);
    return b;
}
