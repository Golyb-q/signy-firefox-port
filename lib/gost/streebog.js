// GOST R 34.11-2012 / GOST 34.11-2015 "Streebog" hash (256 and 512 bit).
// Port of BouncyCastle/Kalkan GOST3411_2012Digest: internal state is kept in reversed (big-endian)
// byte order and the digest is output reversed, i.e. in the conventional little-endian vector order
// (same bytes as produced by BouncyCastle, Kalkan, OpenSSL gost-engine, pygost).
import { C_HEX, T_HEX } from './streebog-tables.js';

const C = C_HEX.map((h) => {
  const b = new Uint8Array(64);
  for (let i = 0; i < 64; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
  return b;
});

// T tables as 32-bit halves: THI[j][b], TLO[j][b]
const THI = [];
const TLO = [];
for (let j = 0; j < 8; j++) {
  const hi = new Int32Array(256);
  const lo = new Int32Array(256);
  const s = T_HEX[j];
  for (let b = 0; b < 256; b++) {
    hi[b] = parseInt(s.substr(b * 16, 8), 16) | 0;
    lo[b] = parseInt(s.substr(b * 16 + 8, 8), 16) | 0;
  }
  THI.push(hi);
  TLO.push(lo);
}

const ZERO = new Uint8Array(64);
const IV512 = new Uint8Array(64);
const IV256 = new Uint8Array(64).fill(1);

const resHi = new Int32Array(8);
const resLo = new Int32Array(8);

function F(V) {
  for (let k = 0; k < 8; k++) {
    let hi = 0, lo = 0;
    for (let j = 0; j < 8; j++) {
      const b = V[8 * (7 - j) + k];
      hi ^= THI[j][b];
      lo ^= TLO[j][b];
    }
    resHi[k] = hi;
    resLo[k] = lo;
  }
  for (let k = 0; k < 8; k++) {
    const hi = resHi[k], lo = resLo[k];
    const o = 8 * k;
    V[o + 7] = hi >>> 24; V[o + 6] = hi >>> 16; V[o + 5] = hi >>> 8; V[o + 4] = hi;
    V[o + 3] = lo >>> 24; V[o + 2] = lo >>> 16; V[o + 1] = lo >>> 8; V[o] = lo;
  }
}

function xor512(A, B) {
  for (let i = 0; i < 64; i++) A[i] ^= B[i];
}

export class Streebog {
  constructor(bits = 512) {
    if (bits !== 256 && bits !== 512) throw new Error('Streebog: bits must be 256 or 512');
    this.bits = bits;
    this.digestSize = bits / 8;
    this.blockSize = 64;
    this.IV = bits === 512 ? IV512 : IV256;
    this.N = new Uint8Array(64);
    this.Sigma = new Uint8Array(64);
    this.Ki = new Uint8Array(64);
    this.m = new Uint8Array(64);
    this.h = new Uint8Array(this.IV);
    this.tmp = new Uint8Array(64);
    this.block = new Uint8Array(64);
    this.bOff = 64;
  }

  E(K, m) {
    const Ki = this.Ki;
    Ki.set(K);
    xor512(K, m);
    F(K);
    for (let i = 0; i < 11; i++) {
      xor512(Ki, C[i]);
      F(Ki);
      xor512(K, Ki);
      F(K);
    }
    xor512(Ki, C[11]);
    F(Ki);
    xor512(K, Ki);
  }

  gN(h, N, m) {
    const tmp = this.tmp;
    tmp.set(h);
    xor512(h, N);
    F(h);
    this.E(h, m);
    xor512(h, tmp);
    xor512(h, m);
  }

  static addMod512Int(A, num) {
    let c = A[63] + (num & 0xff);
    A[63] = c & 0xff;
    c = A[62] + ((num >> 8) & 0xff) + (c >> 8);
    A[62] = c & 0xff;
    for (let i = 61; i >= 0 && c > 0; i--) {
      c = A[i] + (c >> 8);
      A[i] = c & 0xff;
    }
  }

  static addMod512(A, B) {
    let c = 0;
    for (let i = 63; i >= 0; i--) {
      c = A[i] + B[i] + (c >> 8);
      A[i] = c & 0xff;
    }
  }

  processBlock() {
    this.gN(this.h, this.N, this.block);
    Streebog.addMod512Int(this.N, 512);
    Streebog.addMod512(this.Sigma, this.block);
    this.bOff = 64;
  }

  update(data) {
    let i = 0;
    let len = data.length;
    while (this.bOff !== 64 && len > 0) {
      this.block[--this.bOff] = data[i++];
      len--;
      if (this.bOff === 0) this.processBlock();
    }
    while (len >= 64) {
      const block = this.block;
      for (let j = 0; j < 64; j++) block[63 - j] = data[i + j];
      this.gN(this.h, this.N, block);
      Streebog.addMod512Int(this.N, 512);
      Streebog.addMod512(this.Sigma, block);
      i += 64;
      len -= 64;
    }
    while (len > 0) {
      this.block[--this.bOff] = data[i++];
      len--;
      if (this.bOff === 0) this.processBlock();
    }
    return this;
  }

  digest() {
    const lenM = 64 - this.bOff;
    const m = this.m;
    m.fill(0);
    m[63 - lenM] = 1;
    if (this.bOff !== 64) m.set(this.block.subarray(this.bOff, 64), 64 - lenM);
    this.gN(this.h, this.N, m);
    Streebog.addMod512Int(this.N, lenM * 8);
    Streebog.addMod512(this.Sigma, m);
    this.gN(this.h, ZERO, this.N);
    this.gN(this.h, ZERO, this.Sigma);
    const out = new Uint8Array(64);
    for (let j = 0; j < 64; j++) out[63 - j] = this.h[j];
    // 256-bit variant: BouncyCastle copies the first 32 bytes of the reversed state
    return this.bits === 512 ? out : out.slice(32);
  }
}
