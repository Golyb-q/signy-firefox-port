// Synchronous SHA-1 / SHA-256 / SHA-384 / SHA-512 (FIPS 180-4).
// Used where WebCrypto's async API is inconvenient (PKCS#12 KDF, HMAC chains, streaming).

class BlockHash {
  constructor(blockSize) {
    this.blockSize = blockSize;
    this.buf = new Uint8Array(blockSize);
    this.bufLen = 0;
    this.total = 0; // bytes (safe up to 2^53)
  }
  update(data) {
    let off = 0;
    this.total += data.length;
    if (this.bufLen) {
      const take = Math.min(this.blockSize - this.bufLen, data.length);
      this.buf.set(data.subarray(0, take), this.bufLen);
      this.bufLen += take;
      off = take;
      if (this.bufLen === this.blockSize) {
        this.compress(this.buf, 0);
        this.bufLen = 0;
      }
    }
    while (off + this.blockSize <= data.length) {
      this.compress(data, off);
      off += this.blockSize;
    }
    if (off < data.length) {
      this.buf.set(data.subarray(off), 0);
      this.bufLen = data.length - off;
    }
    return this;
  }
  pad(lenBytes) {
    const bits = this.total * 8;
    const padLen = (this.bufLen < this.blockSize - lenBytes ? this.blockSize : 2 * this.blockSize) - this.bufLen;
    const pad = new Uint8Array(padLen);
    pad[0] = 0x80;
    // big-endian length in the last 8 bytes (upper bytes zero for <2^53)
    const hi = Math.floor(bits / 0x100000000);
    const lo = bits >>> 0;
    pad[padLen - 8] = (hi >>> 24) & 255;
    pad[padLen - 7] = (hi >>> 16) & 255;
    pad[padLen - 6] = (hi >>> 8) & 255;
    pad[padLen - 5] = hi & 255;
    pad[padLen - 4] = (lo >>> 24) & 255;
    pad[padLen - 3] = (lo >>> 16) & 255;
    pad[padLen - 2] = (lo >>> 8) & 255;
    pad[padLen - 1] = lo & 255;
    const total = this.total;
    this.update(pad);
    this.total = total;
  }
}

export class SHA1 extends BlockHash {
  constructor() {
    super(64);
    this.h = new Int32Array([0x67452301, 0xefcdab89 | 0, 0x98badcfe | 0, 0x10325476, 0xc3d2e1f0 | 0]);
    this.w = new Int32Array(80);
    this.digestSize = 20;
  }
  compress(d, o) {
    const w = this.w;
    for (let i = 0; i < 16; i++) w[i] = (d[o + 4 * i] << 24) | (d[o + 4 * i + 1] << 16) | (d[o + 4 * i + 2] << 8) | d[o + 4 * i + 3];
    for (let i = 16; i < 80; i++) {
      const x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = (x << 1) | (x >>> 31);
    }
    let [a, b, c, dd, e] = this.h;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b & c) | (~b & dd); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ dd; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & dd) | (c & dd); k = 0x8f1bbcdc | 0; }
      else { f = b ^ c ^ dd; k = 0xca62c1d6 | 0; }
      const t = (((a << 5) | (a >>> 27)) + f + e + k + w[i]) | 0;
      e = dd; dd = c; c = (b << 30) | (b >>> 2); b = a; a = t;
    }
    const h = this.h;
    h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + dd) | 0; h[4] = (h[4] + e) | 0;
  }
  digest() {
    this.pad(8);
    const out = new Uint8Array(20);
    for (let i = 0; i < 5; i++) {
      out[4 * i] = this.h[i] >>> 24; out[4 * i + 1] = this.h[i] >>> 16; out[4 * i + 2] = this.h[i] >>> 8; out[4 * i + 3] = this.h[i];
    }
    return out;
  }
}

const K256 = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export class SHA256 extends BlockHash {
  constructor() {
    super(64);
    this.h = new Int32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    this.w = new Int32Array(64);
    this.digestSize = 32;
  }
  compress(d, o) {
    const w = this.w;
    for (let i = 0; i < 16; i++) w[i] = (d[o + 4 * i] << 24) | (d[o + 4 * i + 1] << 16) | (d[o + 4 * i + 2] << 8) | d[o + 4 * i + 3];
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15], y = w[i - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, dd, e, f, g, h] = this.h;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K256[i] + w[i]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (dd + t1) | 0; dd = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    const H = this.h;
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + dd) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  digest() {
    this.pad(8);
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      out[4 * i] = this.h[i] >>> 24; out[4 * i + 1] = this.h[i] >>> 16; out[4 * i + 2] = this.h[i] >>> 8; out[4 * i + 3] = this.h[i];
    }
    return out;
  }
}

// SHA-512 with 32-bit halves.
const K512 = [
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
].map((x) => x | 0);

export class SHA512 extends BlockHash {
  constructor(is384 = false) {
    super(128);
    this.h = new Int32Array(is384
      ? [0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507, 0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939, 0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511, 0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4]
      : [0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1, 0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179]);
    this.w = new Int32Array(160);
    this.digestSize = is384 ? 48 : 64;
  }
  compress(d, o) {
    const W = this.w;
    for (let i = 0; i < 32; i++) W[i] = (d[o + 4 * i] << 24) | (d[o + 4 * i + 1] << 16) | (d[o + 4 * i + 2] << 8) | d[o + 4 * i + 3];
    for (let i = 16; i < 80; i++) {
      // sigma0 of W[i-15]
      let xh = W[(i - 15) * 2], xl = W[(i - 15) * 2 + 1];
      const s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
      const s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));
      xh = W[(i - 2) * 2]; xl = W[(i - 2) * 2 + 1];
      const s1h = ((xh >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (xh << 3)) ^ (xh >>> 6);
      const s1l = ((xl >>> 19) | (xh << 13)) ^ ((xh >>> 29) | (xl << 3)) ^ ((xl >>> 6) | (xh << 26));
      let lo = (s0l >>> 0) + (s1l >>> 0) + (W[(i - 7) * 2 + 1] >>> 0) + (W[(i - 16) * 2 + 1] >>> 0);
      const hi = s0h + s1h + W[(i - 7) * 2] + W[(i - 16) * 2] + Math.floor(lo / 0x100000000);
      W[i * 2] = hi | 0;
      W[i * 2 + 1] = lo | 0;
    }
    const H = this.h;
    let ah = H[0], al = H[1], bh = H[2], bl = H[3], ch = H[4], cl = H[5], dh = H[6], dl = H[7];
    let eh = H[8], el = H[9], fh = H[10], fl = H[11], gh = H[12], gl = H[13], hh = H[14], hl = H[15];
    for (let i = 0; i < 80; i++) {
      const S1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23));
      const S1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23));
      const chh = (eh & fh) ^ (~eh & gh);
      const chl = (el & fl) ^ (~el & gl);
      let t1l = (hl >>> 0) + (S1l >>> 0) + (chl >>> 0) + (K512[i * 2 + 1] >>> 0) + (W[i * 2 + 1] >>> 0);
      let t1h = hh + S1h + chh + K512[i * 2] + W[i * 2] + Math.floor(t1l / 0x100000000);
      t1l |= 0; t1h |= 0;
      const S0h = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25));
      const S0l = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25));
      const majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
      const majl = (al & bl) ^ (al & cl) ^ (bl & cl);
      let t2l = (S0l >>> 0) + (majl >>> 0);
      const t2h = S0h + majh + Math.floor(t2l / 0x100000000);
      t2l |= 0;
      hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;
      let nl = (dl >>> 0) + (t1l >>> 0);
      eh = (dh + t1h + Math.floor(nl / 0x100000000)) | 0; el = nl | 0;
      dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al;
      nl = (t1l >>> 0) + (t2l >>> 0);
      ah = (t1h + t2h + Math.floor(nl / 0x100000000)) | 0; al = nl | 0;
    }
    const add = (idx, h, l) => {
      const lo = (H[idx + 1] >>> 0) + (l >>> 0);
      H[idx] = (H[idx] + h + Math.floor(lo / 0x100000000)) | 0;
      H[idx + 1] = lo | 0;
    };
    add(0, ah, al); add(2, bh, bl); add(4, ch, cl); add(6, dh, dl);
    add(8, eh, el); add(10, fh, fl); add(12, gh, gl); add(14, hh, hl);
  }
  digest() {
    // 128-bit length; we only fill low 64 bits
    const bits = this.total * 8;
    const padLen = (this.bufLen < 112 ? 128 : 256) - this.bufLen;
    const pad = new Uint8Array(padLen);
    pad[0] = 0x80;
    const hi = Math.floor(bits / 0x100000000), lo = bits >>> 0;
    pad[padLen - 8] = (hi >>> 24) & 255; pad[padLen - 7] = (hi >>> 16) & 255; pad[padLen - 6] = (hi >>> 8) & 255; pad[padLen - 5] = hi & 255;
    pad[padLen - 4] = (lo >>> 24) & 255; pad[padLen - 3] = (lo >>> 16) & 255; pad[padLen - 2] = (lo >>> 8) & 255; pad[padLen - 1] = lo & 255;
    this.update(pad);
    const out = new Uint8Array(this.digestSize);
    for (let i = 0; i < this.digestSize / 4; i++) {
      const v = this.h[i];
      out[4 * i] = v >>> 24; out[4 * i + 1] = v >>> 16; out[4 * i + 2] = v >>> 8; out[4 * i + 3] = v;
    }
    return out;
  }
}
