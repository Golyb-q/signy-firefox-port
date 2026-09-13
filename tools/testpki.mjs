#!/usr/bin/env node
// Generates a self-contained TEST PKI (NOT NCA RK) for development and automated tests:
// root CAs (GOST 34.10-2015/512, GOST 34.310-2004, RSA) and user keys in PKCS#12 files that mimic the
// structure of NCA RK key files (Kalkan/BouncyCastle PKCS#12: 3DES key bag, RC2-40 cert bag, SHA-1 MAC).
//
//   node tools/testpki.mjs [outDir]      (default: test/fixtures/test-pki)
import { mkdirSync, writeFileSync } from 'node:fs';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { der, tlv, decode } from '../extension/lib/asn1.js';
import { OID } from '../extension/lib/oids.js';
import { digest, hmac } from '../extension/lib/hash/index.js';
import { curveByOid } from '../extension/lib/gost/ec.js';
import { signHash, encodeSignature, publicFromPrivate, encodePublicPoint } from '../extension/lib/gost/gost3410.js';
import { rsaSignDigest } from '../extension/lib/signer.js';
import { parsePrivateKeyInfo, pkcs12Kdf } from '../extension/lib/pkcs12.js';
import { DES, cbcEncrypt } from '../extension/lib/cipher/des.js';
import { RC2 } from '../extension/lib/cipher/rc2.js';
import { Certificate, derToPem } from '../extension/lib/x509.js';
import { bigIntToBytesLE, bytesToBigInt, randomBigIntBelow, concat, toHex } from '../extension/lib/util.js';

const u8 = (b) => new Uint8Array(b);

// ---------------------------------------------------------------- keys

function gostKey(kind) {
  const p = {
    GOST2015_512: { algOid: OID.gost3410_2015_512, curveOid: '1.2.398.3.10.1.1.2.2.1', digestOid: OID.gost3411_2015_512, sigOid: OID.gost3411_2015_with_gost3410_2015_512, hash: 'GOST3411-2015-512' },
    GOST2004: { algOid: OID.gost34310_2004, curveOid: '1.2.398.3.10.1.1.1.1.1', digestOid: '1.2.398.3.10.1.3.1.1.0', sigOid: OID.gost34311_95_with_gost34310_2004, hash: 'GOST34311' },
  }[kind];
  const curve = curveByOid(p.curveOid);
  const d = randomBigIntBelow(curve.q);
  const Q = publicFromPrivate(curve, d);
  const algId = der.seq(der.oid(p.algOid), der.seq(der.oid(p.curveOid), der.oid(p.digestOid)));
  const spki = der.seq(algId, der.bit(der.octet(encodePublicPoint(curve, Q))));
  // Kalkan-like private key encodings: 2015 -> OCTET STRING(LE d); 2004 -> SEC1-like SEQUENCE
  const inner = kind === 'GOST2015_512'
    ? der.octet(bigIntToBytesLE(d, curve.bytes))
    : der.seq(der.int(1), der.octet(bigIntToBytesLE(d, curve.bytes)));
  const pkcs8 = der.seq(der.int(0), algId, der.octet(inner));
  return {
    kind, spki, pkcs8, sigOid: p.sigOid,
    sign: (tbs) => encodeSignature(curve, signHash(curve, d, digest(p.hash, tbs))),
  };
}

function rsaKey() {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
  const pkcs8 = u8(privateKey.export({ type: 'pkcs8', format: 'der' }));
  const spki = u8(publicKey.export({ type: 'spki', format: 'der' }));
  const parsed = parsePrivateKeyInfo(pkcs8);
  return { kind: 'RSA', spki, pkcs8, sigOid: OID.sha256WithRSA, sign: (tbs) => rsaSignDigest(parsed, 'SHA-256', digest('SHA-256', tbs)) };
}

// ---------------------------------------------------------------- certificates

function name(rdns) {
  // rdns: [[oid, value, type]] in order; type 'p' printable, default utf8
  return der.seq(...rdns.map(([oid, v, t]) => der.set(der.seq(der.oid(oid), t === 'p' ? der.printable(v) : t === 'ia5' ? der.ia5(v) : der.utf8(v)))));
}

function ext(oid, critical, value) {
  return der.seq(der.oid(oid), critical ? der.bool(true) : null, der.octet(value));
}

function keyUsage(bits) {
  const names = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign'];
  let v = 0;
  bits.forEach((b) => (v |= 0x80 >> names.indexOf(b)));
  // minimal bit string
  let unused = 0;
  while (unused < 7 && !(v & (1 << unused))) unused++;
  return der.bit(new Uint8Array([v]), v ? unused : 0);
}

function ski(spki) {
  const bits = decode(spki).child(1).toBitString().bytes;
  return digest('SHA-1', bits);
}

function makeCert({ serial, issuerName, subjectName, notBefore, notAfter, subjectKey, issuerKey, issuerSpki, ca = false, ku, eku, policies = ['1.2.398.3.3.2.1'], extra = [] }) {
  const exts = [];
  if (ca) exts.push(ext(OID.basicConstraints, true, der.seq(der.bool(true))));
  exts.push(ext(OID.keyUsage, true, keyUsage(ku)));
  if (eku) exts.push(ext(OID.extKeyUsage, false, der.seq(...eku.map((o) => der.oid(o)))));
  exts.push(ext(OID.certificatePolicies, false, der.seq(...policies.map((p) => der.seq(der.oid(p))))));
  exts.push(ext(OID.subjectKeyIdentifier, false, der.octet(ski(subjectKey.spki))));
  exts.push(ext(OID.authorityKeyIdentifier, false, der.seq(der.implicitPrim(0, ski(issuerSpki)))));
  if (!ca) {
    exts.push(ext(OID.crlDistributionPoints, false, der.seq(der.seq(der.explicit(0, der.explicit(0, der.implicitPrim(6, new TextEncoder().encode('http://test.invalid/crl/test.crl'))))))));
    exts.push(ext(OID.authorityInfoAccess, false, der.seq(
      der.seq(der.oid(OID.caIssuers), der.implicitPrim(6, new TextEncoder().encode('http://test.invalid/cert/ca.cer'))),
      der.seq(der.oid(OID.ocsp), der.implicitPrim(6, new TextEncoder().encode('http://test.invalid/ocsp'))),
    )));
  }
  exts.push(...extra);
  const sigAlg = der.seq(der.oid(issuerKey.sigOid), issuerKey.kind === 'RSA' ? der.null() : null);
  const sigAlgGost = issuerKey.kind === 'RSA' ? sigAlg : der.seq(der.oid(issuerKey.sigOid), der.null());
  const tbs = der.seq(
    der.explicit(0, der.int(2)),
    der.int(serial),
    sigAlgGost,
    issuerName,
    der.seq(der.utcTime(notBefore), der.utcTime(notAfter)),
    subjectName,
    subjectKey.spki,
    der.explicit(3, der.seq(...exts)),
  );
  const sig = issuerKey.sign(tbs);
  return new Certificate(der.seq(tbs, sigAlgGost, der.bit(sig)));
}

// ---------------------------------------------------------------- PKCS#12 writer (BouncyCastle-like)

function bmp(pw) {
  const out = new Uint8Array(pw.length * 2 + 2);
  for (let i = 0; i < pw.length; i++) {
    out[2 * i] = pw.charCodeAt(i) >> 8;
    out[2 * i + 1] = pw.charCodeAt(i) & 255;
  }
  return out;
}

function pbeEncrypt(oid, data, password, iter = 2048) {
  const salt = u8(randomBytes(20));
  const pw = bmp(password);
  let enc;
  if (oid === OID.pbeWithSHAAnd3KeyTripleDES) {
    enc = cbcEncrypt(new DES(pkcs12Kdf('SHA-1', pw, salt, iter, 1, 24)), pkcs12Kdf('SHA-1', pw, salt, iter, 2, 8), data);
  } else {
    enc = cbcEncrypt(new RC2(pkcs12Kdf('SHA-1', pw, salt, iter, 1, 5), 40), pkcs12Kdf('SHA-1', pw, salt, iter, 2, 8), data);
  }
  return { alg: der.seq(der.oid(oid), der.seq(der.octet(salt), der.int(iter))), enc };
}

function bagAttrs(localKeyId, friendlyName) {
  return der.set(
    der.seq(der.oid(OID.localKeyId), der.set(der.octet(localKeyId))),
    friendlyName ? der.seq(der.oid(OID.friendlyName), der.set(der.bmp(friendlyName))) : null,
  );
}

export function writePkcs12({ pkcs8, certs, password, alias }) {
  const localKeyId = digest('SHA-1', certs[0].raw);
  const k = pbeEncrypt(OID.pbeWithSHAAnd3KeyTripleDES, pkcs8, password);
  const keyBag = der.seq(der.oid(OID.pkcs8ShroudedKeyBag), der.explicit(0, der.seq(k.alg, der.octet(k.enc))), bagAttrs(localKeyId, alias));
  const keySafe = der.seq(keyBag);
  const certBags = certs.map((c, i) => der.seq(der.oid(OID.certBag), der.explicit(0, der.seq(der.oid(OID.x509Certificate), der.explicit(0, der.octet(c.raw)))), i === 0 ? bagAttrs(localKeyId, alias) : null));
  const certSafe = der.seq(...certBags);
  const ce = pbeEncrypt(OID.pbeWithSHAAnd40BitRC2, certSafe, password);
  const authSafe = der.seq(
    der.seq(der.oid(OID.data), der.explicit(0, der.octet(keySafe))),
    der.seq(der.oid(OID.encryptedData), der.explicit(0, der.seq(der.int(0), der.seq(der.oid(OID.data), ce.alg, der.implicitPrim(0, ce.enc))))),
  );
  const macSalt = u8(randomBytes(20));
  const macKey = pkcs12Kdf('SHA-1', bmp(password), macSalt, 1024, 3, 20);
  const mac = hmac('SHA-1', macKey, authSafe);
  return der.seq(
    der.int(3),
    der.seq(der.oid(OID.data), der.explicit(0, der.octet(authSafe))),
    der.seq(der.seq(der.seq(der.oid('1.3.14.3.2.26'), der.null()), der.octet(mac)), der.octet(macSalt), der.int(1024)),
  );
}

// ---------------------------------------------------------------- scenario

export function makeTestPki() {
  const now = new Date();
  const nb = new Date(now.getTime() - 24 * 3600 * 1000);
  const na = new Date(now.getTime() + 5 * 365 * 24 * 3600 * 1000);
  const caNa = new Date(now.getTime() + 15 * 365 * 24 * 3600 * 1000);
  const EKU_SIGN = [OID.emailProtection];
  const EKU_AUTH = [OID.clientAuth];
  const IND = '1.2.398.3.3.4.1.1';
  const LEGAL_HEAD = '1.2.398.3.3.4.1.2.1';

  const out = { cas: {}, users: {} };

  // Root CAs
  const caGost = gostKey('GOST2015_512');
  const caGostName = name([['2.5.4.3', 'SIGNY TEST CA (GOST) 2025'], ['2.5.4.6', 'KZ', 'p']]);
  out.cas.gost2015 = makeCert({ serial: 0x1001n, issuerName: caGostName, subjectName: caGostName, notBefore: nb, notAfter: caNa, subjectKey: caGost, issuerKey: caGost, issuerSpki: caGost.spki, ca: true, ku: ['keyCertSign', 'cRLSign'] });

  const caGost04 = gostKey('GOST2004');
  const caGost04Name = name([['2.5.4.3', 'SIGNY TEST CA (GOST 2004)'], ['2.5.4.6', 'KZ', 'p']]);
  out.cas.gost2004 = makeCert({ serial: 0x1002n, issuerName: caGost04Name, subjectName: caGost04Name, notBefore: nb, notAfter: caNa, subjectKey: caGost04, issuerKey: caGost04, issuerSpki: caGost04.spki, ca: true, ku: ['keyCertSign', 'cRLSign'] });

  const caRsa = rsaKey();
  const caRsaName = name([['2.5.4.3', 'SIGNY TEST CA (RSA) 2025'], ['2.5.4.6', 'KZ', 'p']]);
  out.cas.rsa = makeCert({ serial: 0x1003n, issuerName: caRsaName, subjectName: caRsaName, notBefore: nb, notAfter: caNa, subjectKey: caRsa, issuerKey: caRsa, issuerSpki: caRsa.spki, ca: true, ku: ['keyCertSign', 'cRLSign'] });

  const person = (extra = []) => name([
    ['2.5.4.3', 'ТЕСТОВ ТЕСТ'], ['2.5.4.4', 'ТЕСТОВ'], ['2.5.4.5', 'IIN123456789011', 'p'], ['2.5.4.6', 'KZ', 'p'], ...extra, ['2.5.4.42', 'ТЕСТОВИЧ'],
  ]);
  const rnd = () => bytesToBigInt(u8(randomBytes(19))) | (1n << 150n);

  const mk = (id, key, ca, caKey, caName, subj, ku, eku, alias) => {
    const cert = makeCert({ serial: rnd(), issuerName: caName, subjectName: subj, notBefore: nb, notAfter: na, subjectKey: key, issuerKey: caKey, issuerSpki: caKey.spki, ku, eku });
    out.users[id] = { cert, p12: writePkcs12({ pkcs8: key.pkcs8, certs: [cert, ca], password: 'Qwerty12', alias }) };
  };

  // Individual, GOST 2015/512: universal key (sign + auth), like current NCA RK keys
  mk('gost2015-individual', gostKey('GOST2015_512'), out.cas.gost2015, caGost, caGostName, person(),
    ['digitalSignature', 'nonRepudiation', 'keyAgreement'], [...EKU_SIGN, EKU_AUTH[0], IND], 'gost2015-individual');
  // Legal entity head, GOST 2015/512
  mk('gost2015-legal', gostKey('GOST2015_512'), out.cas.gost2015, caGost, caGostName,
    person([['2.5.4.10', 'ТОО «SIGNY TEST»'], ['2.5.4.11', 'BIN123456789021', 'p']]),
    ['digitalSignature', 'nonRepudiation'], [...EKU_SIGN, LEGAL_HEAD], 'gost2015-legal');
  // Legacy GOST 34.310-2004
  mk('gost2004-sign', gostKey('GOST2004'), out.cas.gost2004, caGost04, caGost04Name, person(),
    ['digitalSignature', 'nonRepudiation'], [...EKU_SIGN, IND], 'gost2004-sign');
  // RSA: separate AUTH and SIGN keys (older NCA scheme)
  mk('rsa-auth', rsaKey(), out.cas.rsa, caRsa, caRsaName, person(), ['digitalSignature', 'keyEncipherment'], [...EKU_AUTH, IND], 'rsa-auth');
  mk('rsa-sign', rsaKey(), out.cas.rsa, caRsa, caRsaName, person(), ['digitalSignature', 'nonRepudiation'], [...EKU_SIGN, IND], 'rsa-sign');
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const dir = process.argv[2] || new URL('../test/fixtures/test-pki/', import.meta.url).pathname;
  mkdirSync(dir, { recursive: true });
  const pki = makeTestPki();
  for (const [id, c] of Object.entries(pki.cas)) writeFileSync(`${dir}/ca-${id}.pem`, derToPem(c.raw));
  for (const [id, u] of Object.entries(pki.users)) {
    writeFileSync(`${dir}/${id}.p12`, u.p12);
    writeFileSync(`${dir}/${id}.pem`, derToPem(u.cert.raw));
  }
  writeFileSync(`${dir}/README.txt`, 'TEST PKI generated by tools/testpki.mjs. NOT NCA RK. All PKCS#12 passwords: Qwerty12\n');
  console.log('Test PKI written to', dir, Object.keys(pki.users).join(', '));
}

export { toHex, concat, gostKey, rsaKey, makeCert, name, keyUsage, ext };
