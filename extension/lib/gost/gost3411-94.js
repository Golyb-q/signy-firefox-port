// GOST R 34.11-94 / GOST 34.311-95 hash function (port of BouncyCastle/Kalkan GOST3411Digest).
// Kalkan uses S-box "D-TEST" for GOST 34.311-95 (OID 1.2.398.3.10.1.3.1) and "D-A" (CryptoPro)
// for "GOST R 34.11-94" (GOSTR341194Digest).
import { encryptBlock } from './gost28147.js';

const C2 = new Uint8Array([
  0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
  0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff,
]);

export class Gost341194 {
  constructor(sbox = 'D-TEST') {
    this.sbox = sbox;
    this.blockSize = 32;
    this.digestSize = 32;
    this.H = new Uint8Array(32);
    this.Sum = new Uint8Array(32);
    this.xBuf = new Uint8Array(32);
    this.xBufOff = 0;
    this.byteCount = 0;
    this.C = [new Uint8Array(32), new Uint8Array(32), new Uint8Array(C2), new Uint8Array(32)];
    // scratch
    this.K = new Uint8Array(32);
    this.S = new Uint8Array(32);
    this.U = new Uint8Array(32);
    this.V = new Uint8Array(32);
    this.W = new Uint8Array(32);
    this.M = new Uint8Array(32);
    this.a = new Uint8Array(8);
  }

  update(data) {
    let i = 0;
    const n = data.length;
    // fill partial buffer
    while (this.xBufOff !== 0 && i < n) this.updateByte(data[i++]);
    // whole blocks
    while (n - i >= 32) {
      const block = data.subarray(i, i + 32);
      this.sumByteArray(block);
      this.processBlock(block, 0);
      i += 32;
      this.byteCount += 32;
    }
    while (i < n) this.updateByte(data[i++]);
    return this;
  }

  updateByte(b) {
    this.xBuf[this.xBufOff++] = b;
    if (this.xBufOff === 32) {
      this.sumByteArray(this.xBuf);
      this.processBlock(this.xBuf, 0);
      this.xBufOff = 0;
    }
    this.byteCount++;
  }

  P(inp) {
    const K = this.K;
    for (let k = 0; k < 8; k++) {
      K[4 * k] = inp[k];
      K[1 + 4 * k] = inp[8 + k];
      K[2 + 4 * k] = inp[16 + k];
      K[3 + 4 * k] = inp[24 + k];
    }
    return K;
  }

  A(inp) {
    const a = this.a;
    for (let j = 0; j < 8; j++) a[j] = inp[j] ^ inp[j + 8];
    inp.copyWithin(0, 8, 32);
    inp.set(a, 24);
    return inp;
  }

  fw(inp) {
    // treat as 16 little-endian 16-bit words; shift left by one word with feedback
    const w0 = inp[0] | (inp[1] << 8);
    const w1 = inp[2] | (inp[3] << 8);
    const w2 = inp[4] | (inp[5] << 8);
    const w3 = inp[6] | (inp[7] << 8);
    const w12 = inp[24] | (inp[25] << 8);
    const w15 = inp[30] | (inp[31] << 8);
    const nw = w0 ^ w1 ^ w2 ^ w3 ^ w12 ^ w15;
    inp.copyWithin(0, 2, 32);
    inp[30] = nw & 0xff;
    inp[31] = (nw >> 8) & 0xff;
  }

  processBlock(inp, off) {
    const { H, S, U, V, W, M, C } = this;
    M.set(inp.subarray(off, off + 32));
    U.set(H);
    V.set(M);
    for (let j = 0; j < 32; j++) W[j] = U[j] ^ V[j];
    encryptBlock(this.sbox, this.P(W), H, 0, S, 0);
    for (let i = 1; i < 4; i++) {
      const tmpA = this.A(U);
      for (let j = 0; j < 32; j++) U[j] = tmpA[j] ^ C[i][j];
      this.A(this.A(V));
      for (let j = 0; j < 32; j++) W[j] = U[j] ^ V[j];
      encryptBlock(this.sbox, this.P(W), H, i * 8, S, i * 8);
    }
    for (let n = 0; n < 12; n++) this.fw(S);
    for (let n = 0; n < 32; n++) S[n] ^= M[n];
    this.fw(S);
    for (let n = 0; n < 32; n++) S[n] = H[n] ^ S[n];
    for (let n = 0; n < 61; n++) this.fw(S);
    H.set(S);
  }

  sumByteArray(inp) {
    let carry = 0;
    const Sum = this.Sum;
    for (let i = 0; i < 32; i++) {
      const s = Sum[i] + inp[i] + carry;
      Sum[i] = s & 0xff;
      carry = s >>> 8;
    }
  }

  digest() {
    const L = new Uint8Array(32);
    // bit length, little-endian 64-bit
    let bits = this.byteCount * 8;
    for (let i = 0; i < 8; i++) {
      L[i] = bits % 256;
      bits = Math.floor(bits / 256);
    }
    while (this.xBufOff !== 0) this.updateByte(0);
    this.processBlock(L, 0);
    this.processBlock(this.Sum, 0);
    return new Uint8Array(this.H);
  }
}
