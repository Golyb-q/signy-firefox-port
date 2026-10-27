// GOST 28147-89 block cipher (ECB encryption of a single 64-bit block).
// Byte/word conventions follow BouncyCastle / Kalkan GOST28147Engine (little-endian words).

// S-boxes: 8 rows of 16 nibbles, row i is used for the i-th 4-bit group (LSB first).
export const SBOX = {
  // GOST R 34.11-94 "test" parameter set - used by Kalkan for GOST 34.311-95 (1.2.398.3.10.1.3.1)
  'D-TEST': [
    4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3,
    14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9,
    5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11,
    7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3,
    6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2,
    4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14,
    13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12,
    1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12,
  ],
  // GOST R 34.11-94 CryptoPro parameter set (1.2.643.2.2.30.1)
  'D-A': [
    10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15,
    5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8,
    7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13,
    4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3,
    7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5,
    7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3,
    13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11,
    1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12,
  ],
};

/** Precompute 4 combined 8-bit substitution tables (with the 11-bit rotation folded in) for speed. */
function expandSbox(s) {
  const t = [new Int32Array(256), new Int32Array(256), new Int32Array(256), new Int32Array(256)];
  for (let i = 0; i < 4; i++) {
    for (let b = 0; b < 256; b++) {
      const v = (s[32 * i + (b & 15)] | (s[32 * i + 16 + (b >> 4)] << 4)) << (8 * i);
      t[i][b] = (v << 11) | (v >>> 21);
    }
  }
  return t;
}

const expanded = new Map();
function tablesFor(name) {
  let t = expanded.get(name);
  if (!t) {
    t = expandSbox(SBOX[name]);
    expanded.set(name, t);
  }
  return t;
}

/**
 * Encrypt one 8-byte block. key: 32 bytes. Writes result to out[outOff..].
 */
export function encryptBlock(sboxName, key, input, inOff, out, outOff) {
  const T = tablesFor(sboxName);
  const T0 = T[0], T1 = T[1], T2 = T[2], T3 = T[3];
  const k = new Int32Array(8);
  for (let i = 0; i < 8; i++) k[i] = key[4 * i] | (key[4 * i + 1] << 8) | (key[4 * i + 2] << 16) | (key[4 * i + 3] << 24);
  let n1 = input[inOff] | (input[inOff + 1] << 8) | (input[inOff + 2] << 16) | (input[inOff + 3] << 24);
  let n2 = input[inOff + 4] | (input[inOff + 5] << 8) | (input[inOff + 6] << 16) | (input[inOff + 7] << 24);
  const f = (x) => T0[x & 255] | T1[(x >>> 8) & 255] | T2[(x >>> 16) & 255] | T3[x >>> 24];
  for (let r = 0; r < 3; r++) {
    for (let j = 0; j < 8; j++) {
      const t = n1;
      n1 = n2 ^ f((n1 + k[j]) | 0);
      n2 = t;
    }
  }
  for (let j = 7; j > 0; j--) {
    const t = n1;
    n1 = n2 ^ f((n1 + k[j]) | 0);
    n2 = t;
  }
  n2 = n2 ^ f((n1 + k[0]) | 0);
  out[outOff] = n1; out[outOff + 1] = n1 >>> 8; out[outOff + 2] = n1 >>> 16; out[outOff + 3] = n1 >>> 24;
  out[outOff + 4] = n2; out[outOff + 5] = n2 >>> 8; out[outOff + 6] = n2 >>> 16; out[outOff + 7] = n2 >>> 24;
}
