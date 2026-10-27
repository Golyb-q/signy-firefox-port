// DES / Triple-DES (EDE) in CBC mode. Needed only for legacy PKCS#12 PBE
// (pbeWithSHAAnd3-KeyTripleDES-CBC is what Kalkan/NCA key files use).

const PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];
const PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];
const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
const FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];
const E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
const P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
const S = [
  [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
];

// SP[i][6-bit] = P(S_i output placed at its nibble position) as 32-bit value
const SP = S.map((box, i) => {
  const t = new Int32Array(64);
  for (let x = 0; x < 64; x++) {
    const row = ((x & 0x20) >> 4) | (x & 1);
    const col = (x >> 1) & 15;
    const v = box[row * 16 + col] << (28 - 4 * i); // bits 1..32 numbered from MSB
    let out = 0;
    for (let j = 0; j < 32; j++) if (v & (1 << (32 - P[j]))) out |= 1 << (31 - j);
    t[x] = out;
  }
  return t;
});

function getBit(bytes, pos) {
  // pos: 1-based from MSB of bytes[0]
  return (bytes[(pos - 1) >> 3] >> (7 - ((pos - 1) & 7))) & 1;
}

function subkeys(key8) {
  const cd = PC1.map((p) => getBit(key8, p));
  let c = cd.slice(0, 28);
  let d = cd.slice(28);
  const keys = [];
  for (let r = 0; r < 16; r++) {
    for (let s = 0; s < SHIFTS[r]; s++) {
      c.push(c.shift());
      d.push(d.shift());
    }
    const cdr = c.concat(d);
    const k = PC2.map((p) => cdr[p - 1]);
    // pack to 8 six-bit groups
    const groups = new Uint8Array(8);
    for (let g = 0; g < 8; g++) {
      let v = 0;
      for (let b = 0; b < 6; b++) v = (v << 1) | k[g * 6 + b];
      groups[g] = v;
    }
    keys.push(groups);
  }
  return keys;
}

function permute64(block, table) {
  const out = new Uint8Array(8);
  for (let i = 0; i < 64; i++) if (getBit(block, table[i])) out[i >> 3] |= 0x80 >> (i & 7);
  return out;
}

function f(R, k) {
  let out = 0;
  for (let g = 0; g < 8; g++) {
    let v = 0;
    for (let b = 0; b < 6; b++) {
      const pos = E[g * 6 + b]; // 1..32 from MSB
      v = (v << 1) | ((R >>> (32 - pos)) & 1);
    }
    out |= SP[g][v ^ k[g]];
  }
  return out;
}

function desBlock(keys, input, decrypt) {
  const b = permute64(input, IP);
  let L = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
  let R = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7];
  for (let r = 0; r < 16; r++) {
    const k = keys[decrypt ? 15 - r : r];
    const t = R;
    R = L ^ f(R, k);
    L = t;
  }
  const pre = new Uint8Array([R >>> 24, R >>> 16, R >>> 8, R, L >>> 24, L >>> 16, L >>> 8, L]);
  return permute64(pre, FP);
}

export class DES {
  constructor(key) {
    if (key.length === 8) this.ks = [subkeys(key)];
    else if (key.length === 16) this.ks = [subkeys(key.subarray(0, 8)), subkeys(key.subarray(8, 16)), subkeys(key.subarray(0, 8))];
    else if (key.length === 24) this.ks = [subkeys(key.subarray(0, 8)), subkeys(key.subarray(8, 16)), subkeys(key.subarray(16, 24))];
    else throw new Error('DES key must be 8, 16 or 24 bytes');
    this.blockSize = 8;
  }
  encryptBlock(block) {
    if (this.ks.length === 1) return desBlock(this.ks[0], block, false);
    return desBlock(this.ks[2], desBlock(this.ks[1], desBlock(this.ks[0], block, false), true), false);
  }
  decryptBlock(block) {
    if (this.ks.length === 1) return desBlock(this.ks[0], block, true);
    return desBlock(this.ks[0], desBlock(this.ks[1], desBlock(this.ks[2], block, true), false), true);
  }
}

/** Generic CBC with PKCS#5 padding for 8-byte block ciphers. */
export function cbcDecrypt(cipher, iv, data, unpad = true) {
  const bs = cipher.blockSize;
  if (data.length % bs) throw new Error('CBC: ciphertext length is not a multiple of block size');
  const out = new Uint8Array(data.length);
  let prev = iv;
  for (let i = 0; i < data.length; i += bs) {
    const blk = data.subarray(i, i + bs);
    const d = cipher.decryptBlock(blk);
    for (let j = 0; j < bs; j++) out[i + j] = d[j] ^ prev[j];
    prev = blk;
  }
  if (!unpad) return out;
  const pad = out[out.length - 1];
  if (pad < 1 || pad > bs) throw new Error('bad padding');
  for (let i = out.length - pad; i < out.length; i++) if (out[i] !== pad) throw new Error('bad padding');
  return out.slice(0, out.length - pad);
}

export function cbcEncrypt(cipher, iv, data) {
  const bs = cipher.blockSize;
  const pad = bs - (data.length % bs);
  const padded = new Uint8Array(data.length + pad);
  padded.set(data);
  padded.fill(pad, data.length);
  const out = new Uint8Array(padded.length);
  let prev = iv;
  for (let i = 0; i < padded.length; i += bs) {
    const x = new Uint8Array(bs);
    for (let j = 0; j < bs; j++) x[j] = padded[i + j] ^ prev[j];
    const e = cipher.encryptBlock(x);
    out.set(e, i);
    prev = e;
  }
  return out;
}
