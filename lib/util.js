// Byte / encoding helpers shared by the whole crypto library.
// Everything works on Uint8Array; BigInt is used for big numbers.

export function concat(...arrays) {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function reverseBytes(a) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[a.length - 1 - i];
  return out;
}

export function toHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

export function fromHex(hex) {
  hex = hex.replace(/[^0-9a-fA-F]/g, '');
  if (hex.length % 2) hex = '0' + hex;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP = new Int16Array(256).fill(-1);
for (let i = 0; i < B64.length; i++) B64_LOOKUP[B64.charCodeAt(i)] = i;
B64_LOOKUP['-'.charCodeAt(0)] = 62; // base64url tolerance
B64_LOOKUP['_'.charCodeAt(0)] = 63;

export function toBase64(bytes) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  if (i < bytes.length) {
    const n = (bytes[i] << 16) | ((i + 1 < bytes.length ? bytes[i + 1] : 0) << 8);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
    out += i + 1 < bytes.length ? B64[(n >> 6) & 63] + '=' : '==';
  }
  return out;
}

/** Lenient base64 decoder (ignores whitespace, accepts url-safe alphabet and missing padding). */
export function fromBase64(str) {
  if (typeof str !== 'string') throw new TypeError('base64 input must be a string');
  const clean = [];
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c === 61) break; // '='
    const v = B64_LOOKUP[c];
    if (v >= 0) clean.push(v);
    else if (c === 32 || c === 9 || c === 10 || c === 13) continue;
    else throw new Error('Invalid base64 character at position ' + i);
  }
  const out = new Uint8Array(Math.floor((clean.length * 6) / 8));
  let o = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const n = (clean[i] << 18) | ((clean[i + 1] ?? 0) << 12) | ((clean[i + 2] ?? 0) << 6) | (clean[i + 3] ?? 0);
    if (o < out.length) out[o++] = (n >> 16) & 255;
    if (o < out.length) out[o++] = (n >> 8) & 255;
    if (o < out.length) out[o++] = n & 255;
  }
  return out;
}

/** Strict check used when the caller claims that data is base64 (NCALayer "decode" flag). */
export function isBase64(str) {
  return typeof str === 'string' && /^[A-Za-z0-9+/\r\n\t =_-]*$/.test(str);
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8');
const fatalDecoder = new TextDecoder('utf-8', { fatal: true });

export function utf8Encode(str) {
  return encoder.encode(str);
}

export function utf8Decode(bytes) {
  return decoder.decode(bytes);
}

/** Returns decoded string or null when bytes are not valid UTF-8. */
export function tryUtf8Decode(bytes) {
  try {
    return fatalDecoder.decode(bytes);
  } catch {
    return null;
  }
}

// ---- BigInt helpers -------------------------------------------------------

export function bytesToBigInt(bytes) {
  if (bytes.length === 0) return 0n;
  return BigInt('0x' + toHex(bytes));
}

export function bytesToBigIntLE(bytes) {
  return bytesToBigInt(reverseBytes(bytes));
}

export function bigIntToBytes(n, len) {
  if (n < 0n) throw new RangeError('negative bigint');
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let bytes = fromHex(hex);
  if (len !== undefined) {
    if (bytes.length > len) {
      // allow leading zero trimming only
      const extra = bytes.length - len;
      for (let i = 0; i < extra; i++) if (bytes[i] !== 0) throw new RangeError('bigint too large for ' + len + ' bytes');
      bytes = bytes.slice(extra);
    } else if (bytes.length < len) {
      const out = new Uint8Array(len);
      out.set(bytes, len - bytes.length);
      bytes = out;
    }
  }
  return bytes;
}

export function bigIntToBytesLE(n, len) {
  return reverseBytes(bigIntToBytes(n, len));
}

/** Java BigInteger.toByteArray() compatible (two's complement, minimal, big-endian) for non-negative values. */
export function bigIntToJavaBytes(n) {
  if (n === 0n) return new Uint8Array([0]);
  let bytes = bigIntToBytes(n);
  if (bytes[0] & 0x80) bytes = concat(new Uint8Array([0]), bytes);
  return bytes;
}

export function mod(a, m) {
  const r = a % m;
  return r < 0n ? r + m : r;
}

export function modPow(base, exp, m) {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return result;
}

export function modInv(a, m) {
  // extended Euclid
  let [oldR, r] = [mod(a, m), m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('not invertible');
  return mod(oldS, m);
}

export function bitLength(n) {
  return n === 0n ? 0 : n.toString(2).length;
}

export function randomBytes(len) {
  const out = new Uint8Array(len);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** Uniform random BigInt in [1, max-1]. */
export function randomBigIntBelow(max) {
  const bytes = Math.ceil(bitLength(max) / 8);
  const bits = bitLength(max);
  const mask = (1n << BigInt(bits)) - 1n;
  for (;;) {
    const r = bytesToBigInt(randomBytes(bytes)) & mask;
    if (r > 0n && r < max) return r;
  }
}

export function wipe(bytes) {
  if (bytes && typeof bytes.fill === 'function') bytes.fill(0);
}
