// High-level signing key: wraps a private key + certificate and produces signatures in Kalkan format.
import { OID, SIG_ALGS } from './oids.js';
import { digest } from './hash/index.js';
import { signHash as gostSignHash, encodeSignature as gostEncode } from './gost/gost3410.js';
import { digestInfo } from './x509.js';
import { bigIntToBytes, bytesToBigInt, modPow, mod, concat } from './util.js';

const RSA_HASHES = new Set(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']);

/** Hash that Kalkan uses for a key's "native" signature algorithm (basics "raw" format, TSP, etc.) */
export function nativeHashFor(key) {
  if (key.type === 'RSA') return 'SHA-256';
  switch (key.algOid) {
    case OID.gost3410_2015_512:
    case OID.gost2012_512:
      return 'GOST3411-2015-512';
    case OID.gost3410_2015_256:
    case OID.gost2012_256:
      return 'GOST3411-2015-256';
    default:
      return 'GOST34311';
  }
}

export class SigningKey {
  /** @param entry { key, cert, chain } from parsePkcs12 */
  constructor(entry) {
    this.key = entry.key;
    this.cert = entry.cert;
    this.chain = entry.chain || [entry.cert];
    this.alias = entry.alias;
  }

  get type() {
    return this.key.type;
  }

  /**
   * Digest algorithm Kalkan selects for CMS/XML signatures: it is derived from the *certificate's*
   * signature algorithm OID (CMSUtil / XMLUtil in knca_provider_util).
   */
  get certHashName() {
    const alg = SIG_ALGS[this.cert.sigAlgOid];
    if (!alg || !alg.hash) throw new Error('Неподдерживаемый алгоритм сертификата: ' + this.cert.sigAlgOid);
    return alg.hash;
  }

  /** Signs `data` with hash `hashName`. Returns signature bytes (PKCS#1 v1.5 for RSA, Kalkan format for GOST). */
  async sign(hashName, data) {
    if (this.key.type === 'RSA') return rsaSign(this.key, hashName, data);
    if (this.key.type === 'GOST') {
      const h = digest(hashName, data);
      return gostEncode(this.key.curve, gostSignHash(this.key.curve, this.key.d, h));
    }
    throw new Error('Неподдерживаемый тип ключа');
  }

  /** Signs a pre-computed hash. */
  async signDigest(hashName, hash) {
    if (this.key.type === 'RSA') return rsaSignDigest(this.key, hashName, hash);
    return gostEncode(this.key.curve, gostSignHash(this.key.curve, this.key.d, hash));
  }

  /** Forget the private key material (best effort). */
  destroy() {
    if (this.key) {
      if (this.key.pkcs8) this.key.pkcs8.fill(0);
      this.key.d = 0n;
      this.key.dCandidates = [];
      this.key.p = this.key.q = this.key.dp = this.key.dq = this.key.qi = 0n;
    }
    this.key = null;
  }
}

async function rsaSign(key, hashName, data) {
  if (!RSA_HASHES.has(hashName)) throw new Error('RSA: неподдерживаемый хэш ' + hashName);
  const subtle = globalThis.crypto?.subtle;
  if (subtle) {
    try {
      const k = await subtle.importKey('pkcs8', key.pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash: hashName }, false, ['sign']);
      return new Uint8Array(await subtle.sign('RSASSA-PKCS1-v1_5', k, data));
    } catch {
      // fall through to BigInt implementation (e.g. unusual PKCS#8 encodings)
    }
  }
  return rsaSignDigest(key, hashName, digest(hashName, data));
}

/** RSASSA-PKCS1-v1_5 with CRT, BigInt implementation. */
export function rsaSignDigest(key, hashName, hash) {
  const k = Math.ceil(key.n.toString(16).length / 2);
  const t = digestInfo(hashName, hash);
  if (k < t.length + 11) throw new Error('RSA key too short');
  const em = new Uint8Array(k);
  em[0] = 0;
  em[1] = 1;
  em.fill(0xff, 2, k - t.length - 1);
  em[k - t.length - 1] = 0;
  em.set(t, k - t.length);
  const m = bytesToBigInt(em);
  let s;
  if (key.p && key.q && key.dp && key.dq && key.qi) {
    const m1 = modPow(m, key.dp, key.p);
    const m2 = modPow(m, key.dq, key.q);
    const h = mod(key.qi * (m1 - m2), key.p);
    s = m2 + h * key.q;
  } else s = modPow(m, key.d, key.n);
  // verify (fault attack protection)
  if (modPow(s, key.e, key.n) !== m) throw new Error('RSA signature self-check failed');
  return bigIntToBytes(s, k);
}

export { concat };
