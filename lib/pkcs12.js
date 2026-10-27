// PKCS#12 (PFX) reader: MAC verification, PBE decryption (PKCS#12 PBE + PBES2), key/cert extraction,
// pairing of private keys with certificates.
import { decode, der, TAG } from './asn1.js';
import { OID, HASH_OIDS } from './oids.js';
import { createHash, HASH, hmac, pbkdf2 } from './hash/index.js';
import { DES, cbcDecrypt } from './cipher/des.js';
import { RC2, rc4 } from './cipher/rc2.js';
import { Certificate } from './x509.js';
import { concat, equalBytes, utf8Encode, bytesToBigInt, bytesToBigIntLE, toHex } from './util.js';
import { curveByOid } from './gost/ec.js';
import { publicFromPrivate } from './gost/gost3410.js';

export class Pkcs12Error extends Error {
  constructor(code, message) {
    super(message || code);
    this.code = code;
  }
}

function bmpPassword(password) {
  if (!password) return new Uint8Array(0);
  const out = new Uint8Array(password.length * 2 + 2);
  for (let i = 0; i < password.length; i++) {
    out[i * 2] = password.charCodeAt(i) >> 8;
    out[i * 2 + 1] = password.charCodeAt(i) & 0xff;
  }
  return out;
}

/** RFC 7292 Appendix B key derivation. */
export function pkcs12Kdf(hashName, pwBytes, salt, iterations, id, n) {
  const { size: u, block: v } = HASH[hashName];
  const D = new Uint8Array(v).fill(id);
  const fill = (src) => {
    if (!src.length) return new Uint8Array(0);
    const len = v * Math.ceil(src.length / v);
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = src[i % src.length];
    return out;
  };
  const S = fill(salt);
  const P = fill(pwBytes);
  const I = concat(S, P);
  const c = Math.ceil(n / u);
  const result = new Uint8Array(c * u);
  for (let i = 0; i < c; i++) {
    let A = createHash(hashName).update(D).update(I).digest();
    for (let r = 1; r < iterations; r++) A = createHash(hashName).update(A).digest();
    result.set(A, i * u);
    if (i < c - 1) {
      const B = new Uint8Array(v);
      for (let k = 0; k < v; k++) B[k] = A[k % u];
      for (let j = 0; j < I.length; j += v) {
        let carry = 1;
        for (let k = v - 1; k >= 0; k--) {
          const s = I[j + k] + B[k] + carry;
          I[j + k] = s & 0xff;
          carry = s >> 8;
        }
      }
    }
  }
  return result.slice(0, n);
}

const PBE_PARAMS = {
  [OID.pbeWithSHAAnd3KeyTripleDES]: { cipher: '3des', keyLen: 24, ivLen: 8 },
  [OID.pbeWithSHAAnd2KeyTripleDES]: { cipher: '3des', keyLen: 16, ivLen: 8 },
  [OID.pbeWithSHAAnd40BitRC2]: { cipher: 'rc2', keyLen: 5, ivLen: 8, bits: 40 },
  [OID.pbeWithSHAAnd128BitRC2]: { cipher: 'rc2', keyLen: 16, ivLen: 8, bits: 128 },
  [OID.pbeWithSHAAnd40BitRC4]: { cipher: 'rc4', keyLen: 5, ivLen: 0 },
  [OID.pbeWithSHAAnd128BitRC4]: { cipher: 'rc4', keyLen: 16, ivLen: 0 },
};

const PRF_HASH = {
  [OID.hmacWithSHA1]: 'SHA-1',
  [OID.hmacWithSHA256]: 'SHA-256',
  [OID.hmacWithSHA384]: 'SHA-384',
  [OID.hmacWithSHA512]: 'SHA-512',
  '1.2.643.7.1.1.4.2': 'GOST3411-2015-512', // HMAC Streebog-512 (TC26)
};

async function aesCbcDecrypt(key, iv, data) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Pkcs12Error('UNSUPPORTED_ALGORITHM', 'AES requires WebCrypto');
  const k = await subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt']);
  return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv }, k, data));
}

async function pbkdf2Any(prfHash, password, salt, iterations, keyLen) {
  const subtle = globalThis.crypto?.subtle;
  if (subtle && ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'].includes(prfHash)) {
    const base = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: prfHash, salt, iterations }, base, keyLen * 8));
  }
  return pbkdf2(prfHash, password, salt, iterations, keyLen);
}

/**
 * Decrypt data protected with an AlgorithmIdentifier (PKCS#12 PBE or PBES2).
 * @returns Promise<Uint8Array>
 */
async function pbeDecrypt(algNode, data, password) {
  const oid = algNode.child(0).toOid();
  const params = algNode.count > 1 ? algNode.child(1) : null;
  if (PBE_PARAMS[oid]) {
    const p = PBE_PARAMS[oid];
    const salt = params.child(0).content;
    const iter = params.count > 1 ? params.child(1).toNumber() : 1;
    const pw = bmpPassword(password);
    const key = pkcs12Kdf('SHA-1', pw, salt, iter, 1, p.keyLen);
    const iv = p.ivLen ? pkcs12Kdf('SHA-1', pw, salt, iter, 2, p.ivLen) : null;
    if (p.cipher === '3des') return cbcDecrypt(new DES(key), iv, data);
    if (p.cipher === 'rc2') return cbcDecrypt(new RC2(key, p.bits), iv, data);
    return rc4(key, data);
  }
  if (oid === OID.pbes2) {
    const kdf = params.child(0);
    const enc = params.child(1);
    if (kdf.child(0).toOid() !== OID.pbkdf2) throw new Pkcs12Error('UNSUPPORTED_ALGORITHM', 'PBES2 KDF ' + kdf.child(0).toOid());
    const kp = kdf.child(1);
    const salt = kp.child(0).content;
    const iter = kp.child(1).toNumber();
    let keyLen = null;
    let prf = 'SHA-1';
    for (let i = 2; i < kp.count; i++) {
      const n = kp.child(i);
      if (n.isUniversal(TAG.INTEGER)) keyLen = n.toNumber();
      else if (n.isUniversal(TAG.SEQUENCE)) {
        prf = PRF_HASH[n.child(0).toOid()];
        if (!prf) throw new Pkcs12Error('UNSUPPORTED_ALGORITHM', 'PBKDF2 PRF ' + n.child(0).toOid());
      }
    }
    const encOid = enc.child(0).toOid();
    const iv = enc.child(1).content;
    const pw = utf8Encode(password || '');
    if ([OID.aes128CBC, OID.aes192CBC, OID.aes256CBC].includes(encOid)) {
      const kl = keyLen || { [OID.aes128CBC]: 16, [OID.aes192CBC]: 24, [OID.aes256CBC]: 32 }[encOid];
      const key = await pbkdf2Any(prf, pw, salt, iter, kl);
      return aesCbcDecrypt(key, iv, data);
    }
    if (encOid === OID.desEDE3CBC) {
      const key = await pbkdf2Any(prf, pw, salt, iter, 24);
      return cbcDecrypt(new DES(key), iv, data);
    }
    if (encOid === OID.desCBC) {
      const key = await pbkdf2Any(prf, pw, salt, iter, 8);
      return cbcDecrypt(new DES(key), iv, data);
    }
    throw new Pkcs12Error('UNSUPPORTED_ALGORITHM', 'PBES2 cipher ' + encOid);
  }
  throw new Pkcs12Error('UNSUPPORTED_ALGORITHM', 'Unsupported PBE algorithm ' + oid);
}

function verifyMac(macData, authSafeContent, password) {
  const digestInfo = macData.child(0);
  const hashOid = digestInfo.child(0).child(0).toOid();
  const hashName = HASH_OIDS[hashOid];
  if (!hashName) throw new Pkcs12Error('UNSUPPORTED_ALGORITHM', 'MAC digest ' + hashOid);
  const expected = digestInfo.child(1).content;
  const salt = macData.child(1).content;
  const iter = macData.count > 2 ? macData.child(2).toNumber() : 1;
  const candidates = password ? [bmpPassword(password)] : [new Uint8Array(0), new Uint8Array(2)];
  for (const pw of candidates) {
    const key = pkcs12Kdf(hashName, pw, salt, iter, 3, HASH[hashName].size);
    if (equalBytes(hmac(hashName, key, authSafeContent), expected)) return true;
  }
  return false;
}

function parseAttributes(setNode) {
  const attrs = {};
  if (!setNode) return attrs;
  for (const a of setNode.children || []) {
    const oid = a.child(0).toOid();
    const vals = a.child(1).children || [];
    if (!vals.length) continue;
    if (oid === OID.localKeyId) attrs.localKeyId = toHex(vals[0].content);
    else if (oid === OID.friendlyName) attrs.friendlyName = vals[0].toStr();
  }
  return attrs;
}

// ---------------------------------------------------------------- private keys

export function parsePrivateKeyInfo(pkcs8) {
  const pki = decode(pkcs8);
  const alg = pki.child(1);
  const algOid = alg.child(0).toOid();
  const keyOctets = pki.child(2).content;
  if (algOid === OID.rsaEncryption) {
    const k = decode(keyOctets);
    const n = (i) => k.child(i).toBigInt();
    return { type: 'RSA', pkcs8, n: n(1), e: n(2), d: n(3), p: n(4), q: n(5), dp: n(6), dq: n(7), qi: n(8), bits: n(1).toString(2).length };
  }
  const gostAlgs = [OID.gost34310_2004, OID.gost3410_2015_512, OID.gost3410_2015_256, OID.gostR3410_2001, OID.gost2012_256, OID.gost2012_512, OID.gostR34310_2004_GT];
  if (gostAlgs.includes(algOid)) {
    const params = alg.count > 1 ? alg.child(1) : null;
    const oids = params && params.children ? params.children.filter((c) => c.isUniversal(TAG.OID)).map((c) => c.toOid()) : [];
    let curveOid = oids[0];
    if (!curveOid) curveOid = [OID.gost3410_2015_512, OID.gost2012_512].includes(algOid) ? '1.2.398.3.10.1.1.2.2.1' : '1.2.398.3.10.1.1.1.1.1';
    const curve = curveByOid(curveOid);
    // Candidate encodings of d (resolved later against the certificate public key).
    const candidates = [];
    try {
      const n = decode(keyOctets);
      if (n.isUniversal(TAG.INTEGER)) candidates.push(n.toBigInt());
      else if (n.isUniversal(TAG.OCTET_STRING)) candidates.push(bytesToBigIntLE(n.content), bytesToBigInt(n.content));
      else if (n.isUniversal(TAG.SEQUENCE)) {
        for (const c of n.children) {
          if (c.isUniversal(TAG.OCTET_STRING)) candidates.push(bytesToBigInt(c.content), bytesToBigIntLE(c.content));
          if (c.isUniversal(TAG.INTEGER) && c.len > 8) candidates.push(c.toBigInt());
        }
      }
    } catch {
      /* raw */
    }
    candidates.push(bytesToBigIntLE(keyOctets), bytesToBigInt(keyOctets));
    const ds = [...new Set(candidates.filter((d) => d > 0n && d < curve.q))];
    return { type: 'GOST', pkcs8, algOid, curveOid, digestOid: oids[1] || null, curve, dCandidates: ds, d: ds[0] };
  }
  return { type: 'UNKNOWN', pkcs8, algOid };
}

/** Checks whether a private key corresponds to a certificate; for GOST also fixes the d encoding. */
export function keyMatchesCertificate(key, cert) {
  const pub = cert.publicKey;
  if (key.type === 'RSA') return pub.type === 'RSA' && pub.n === key.n;
  if (key.type === 'GOST') {
    if (pub.type !== 'GOST' || pub.curve !== key.curve) return false;
    for (const d of key.dCandidates) {
      const Q = publicFromPrivate(key.curve, d);
      if (Q && Q.x === pub.Q.x && Q.y === pub.Q.y) {
        key.d = d;
        return true;
      }
    }
  }
  return false;
}

// ---------------------------------------------------------------- PFX

/**
 * Parse a PKCS#12 file.
 * @returns {Promise<{entries: Array<{alias, key, cert, chain}>, certs: Certificate[]}>}
 */
export async function parsePkcs12(bytes, password) {
  let pfx;
  try {
    pfx = decode(bytes);
  } catch (e) {
    throw new Pkcs12Error('BAD_FORMAT', 'Файл не является контейнером PKCS#12: ' + e.message);
  }
  if (!pfx.isUniversal(TAG.SEQUENCE) || pfx.count < 2) throw new Pkcs12Error('BAD_FORMAT', 'Файл не является контейнером PKCS#12');
  const authSafe = pfx.child(1);
  const ctype = authSafe.child(0).toOid();
  if (ctype !== OID.data) throw new Pkcs12Error('UNSUPPORTED_ALGORITHM', 'PKCS#12 authSafe type ' + ctype);
  const authContent = authSafe.child(1).child(0).toOctets();
  if (pfx.count > 2) {
    if (!verifyMac(pfx.child(2), authContent, password)) throw new Pkcs12Error('WRONG_PASSWORD', 'Неверный пароль');
  }
  const contentInfos = decode(authContent);
  const keys = [];
  const certs = [];

  const handleBags = async (safeContents) => {
    for (const bag of safeContents.children) {
      const bagId = bag.child(0).toOid();
      const value = bag.child(1).child(0);
      const attrs = parseAttributes(bag.count > 2 ? bag.child(2) : null);
      if (bagId === OID.pkcs8ShroudedKeyBag) {
        let pkcs8;
        try {
          pkcs8 = await pbeDecrypt(value.child(0), value.child(1).content, password);
        } catch (e) {
          if (e instanceof Pkcs12Error && e.code === 'UNSUPPORTED_ALGORITHM') throw e;
          throw new Pkcs12Error('WRONG_PASSWORD', 'Неверный пароль');
        }
        keys.push({ ...parsePrivateKeyInfo(pkcs8), attrs });
      } else if (bagId === OID.keyBag) {
        keys.push({ ...parsePrivateKeyInfo(value.bytes), attrs });
      } else if (bagId === OID.certBag) {
        if (value.child(0).toOid() === OID.x509Certificate) {
          const der = value.child(1).child(0).content;
          try {
            certs.push({ cert: new Certificate(der), attrs });
          } catch {
            /* skip malformed cert */
          }
        }
      } else if (bagId === OID.safeContentsBag) {
        await handleBags(value);
      }
    }
  };

  for (const ci of contentInfos.children) {
    const type = ci.child(0).toOid();
    if (type === OID.data) {
      await handleBags(decode(ci.child(1).child(0).toOctets()));
    } else if (type === OID.encryptedData) {
      const ed = ci.child(1).child(0);
      const eci = ed.child(1);
      const alg = eci.child(1);
      const encNode = eci.child(2);
      const enc = encNode.constructed ? concat(...encNode.children.map((c) => c.content)) : encNode.content;
      let plain;
      try {
        plain = await pbeDecrypt(alg, enc, password);
      } catch (e) {
        if (e instanceof Pkcs12Error && e.code === 'UNSUPPORTED_ALGORITHM') throw e;
        throw new Pkcs12Error('WRONG_PASSWORD', 'Неверный пароль');
      }
      await handleBags(decode(plain));
    }
  }

  if (!keys.length) throw new Pkcs12Error('NO_KEYS', 'В хранилище нет закрытых ключей');

  // Pair keys with certificates.
  const allCerts = certs.map((c) => c.cert);
  const entries = [];
  keys.forEach((key, idx) => {
    let match = null;
    if (key.attrs.localKeyId) match = certs.find((c) => c.attrs.localKeyId === key.attrs.localKeyId && keyMatchesCertificate(key, c.cert));
    if (!match) match = certs.find((c) => keyMatchesCertificate(key, c.cert));
    if (!match) return;
    const cert = match.cert;
    entries.push({
      alias: key.attrs.friendlyName || match.attrs.friendlyName || key.attrs.localKeyId || String(idx),
      key,
      cert,
      chain: buildChain(cert, allCerts),
    });
  });
  if (!entries.length) throw new Pkcs12Error('NO_KEYS', 'Не найдено сертификатов, соответствующих ключам');
  return { entries, certs: allCerts };
}

/** Build chain [leaf, issuer, ...] from available certificates (by DN + signature). */
export function buildChain(leaf, pool) {
  const chain = [leaf];
  let cur = leaf;
  for (let depth = 0; depth < 8; depth++) {
    if (cur.isSelfIssued()) break;
    const issuer = pool.find((c) => c !== cur && equalBytes(c.subjectRaw, cur.issuerRaw) && safeVerify(cur, c));
    if (!issuer || chain.includes(issuer)) break;
    chain.push(issuer);
    cur = issuer;
  }
  return chain;
}

function safeVerify(cert, issuer) {
  try {
    return cert.verifySignedBy(issuer);
  } catch {
    return false;
  }
}
