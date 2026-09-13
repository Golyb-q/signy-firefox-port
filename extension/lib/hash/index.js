// Hash registry: names, OIDs and helpers (HMAC, one-shot digest).
import { SHA1, SHA256, SHA512 } from './sha.js';
import { Gost341194 } from '../gost/gost3411-94.js';
import { Streebog } from '../gost/streebog.js';

export const HASH = {
  'SHA-1': { oid: '1.3.14.3.2.26', create: () => new SHA1(), size: 20, block: 64 },
  'SHA-256': { oid: '2.16.840.1.101.3.4.2.1', create: () => new SHA256(), size: 32, block: 64 },
  'SHA-384': { oid: '2.16.840.1.101.3.4.2.2', create: () => new SHA512(true), size: 48, block: 128 },
  'SHA-512': { oid: '2.16.840.1.101.3.4.2.3', create: () => new SHA512(false), size: 64, block: 128 },
  // Kazakhstan GOST 34.311-95 (Kalkan "GOST3411", S-box D-TEST)
  GOST34311: { oid: '1.2.398.3.10.1.3.1', create: () => new Gost341194('D-TEST'), size: 32, block: 32 },
  // GOST R 34.11-94 with CryptoPro parameters (Kalkan "GOST R 34.11-94" / "GT" variant uses D-A)
  'GOSTR3411-94-CP': { oid: '1.2.643.2.2.9', create: () => new Gost341194('D-A'), size: 32, block: 32 },
  'GOST3411-2015-256': { oid: '1.2.398.3.10.1.3.2', create: () => new Streebog(256), size: 32, block: 64 },
  'GOST3411-2015-512': { oid: '1.2.398.3.10.1.3.3', create: () => new Streebog(512), size: 64, block: 64 },
};

// Extra OID aliases seen in the wild
const OID_ALIASES = {
  '1.3.6.1.4.1.6801.1.2.1': 'GOST34311', // Kalkan gostR3411_GT (Kalkan uses its GOST3411 = D-TEST digest)
  '1.2.643.7.1.1.2.2': 'GOST3411-2015-256', // TC26 streebog256
  '1.2.643.7.1.1.2.3': 'GOST3411-2015-512', // TC26 streebog512
};

export function hashByOid(oid) {
  for (const [name, h] of Object.entries(HASH)) if (h.oid === oid) return name;
  return OID_ALIASES[oid] || null;
}

export function createHash(name) {
  const h = HASH[name];
  if (!h) throw new Error('Unsupported hash ' + name);
  return h.create();
}

export function digest(name, data) {
  return createHash(name).update(data).digest();
}

export function hmac(name, key, data) {
  const { block } = HASH[name];
  if (key.length > block) key = digest(name, key);
  const k = new Uint8Array(block);
  k.set(key);
  const ipad = new Uint8Array(block);
  const opad = new Uint8Array(block);
  for (let i = 0; i < block; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  const inner = createHash(name).update(ipad).update(data).digest();
  return createHash(name).update(opad).update(inner).digest();
}

/** PBKDF2 (RFC 8018) with HMAC over any registered hash. Synchronous. */
export function pbkdf2(name, password, salt, iterations, dkLen) {
  const { size } = HASH[name];
  const blocks = Math.ceil(dkLen / size);
  const out = new Uint8Array(blocks * size);
  for (let i = 1; i <= blocks; i++) {
    const s = new Uint8Array(salt.length + 4);
    s.set(salt);
    s[salt.length] = i >>> 24; s[salt.length + 1] = i >>> 16; s[salt.length + 2] = i >>> 8; s[salt.length + 3] = i;
    let u = hmac(name, password, s);
    const t = new Uint8Array(u);
    for (let j = 1; j < iterations; j++) {
      u = hmac(name, password, u);
      for (let k = 0; k < t.length; k++) t[k] ^= u[k];
    }
    out.set(t, (i - 1) * size);
  }
  return out.slice(0, dkLen);
}
