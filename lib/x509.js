// X.509 certificate parsing, DN formatting (Kalkan-compatible) and signature verification.
import { decode, der, TAG } from './asn1.js';
import { OID, SIG_ALGS, DN_SYMBOLS } from './oids.js';
import { toHex, toBase64, fromBase64, bigIntToJavaBytes, bytesToBigInt, modPow, equalBytes, concat } from './util.js';
import { digest } from './hash/index.js';
import { curveByOid } from './gost/ec.js';
import { decodePublicPoint, verifySignature as gostVerify } from './gost/gost3410.js';

// ---------------------------------------------------------------- names

function parseName(node) {
  // Name ::= SEQUENCE OF RelativeDistinguishedName (SET OF AttributeTypeAndValue)
  const rdns = [];
  for (const set of node.children || []) {
    const rdn = [];
    for (const atv of set.children || []) {
      const oid = atv.child(0).toOid();
      const v = atv.child(1);
      let value;
      let isString = true;
      if (v.cls === 0 && [TAG.UTF8, TAG.PRINTABLE, TAG.IA5, TAG.BMP, TAG.T61, TAG.VISIBLE, TAG.NUMERIC].includes(v.tagNum)) value = v.toStr();
      else {
        value = '#' + toHex(v.bytes);
        isString = false;
      }
      rdn.push({ oid, value, isString });
    }
    rdns.push(rdn);
  }
  return rdns;
}

function escapeBcValue(value) {
  let v = value;
  let prefix = '';
  if (v.length >= 2 && v[0] === '\\' && v[1] === '#') {
    prefix = '\\#';
    v = v.slice(2);
  }
  return prefix + v.replace(/[,"\\+=<>;]/g, (c) => '\\' + c);
}

/** Renders a Name like Kalkan/BouncyCastle X509Name.toString() (NCALayer subjectDn / issuerDn). */
export function formatNameKalkan(rdns) {
  const comps = [];
  for (const rdn of rdns) {
    const parts = rdn.map(({ oid, value, isString }) => {
      const sym = DN_SYMBOLS[oid] || oid;
      let v = value;
      if (isString && v.length > 0 && v[0] === '#') v = '\\' + v;
      return sym + '=' + escapeBcValue(v);
    });
    comps.push(parts.join('+'));
  }
  return comps.join(',');
}

/** RFC 4514-ish rendering (reverse order), for display only. */
export function formatNameRfc(rdns) {
  const SHORT = { '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'SERIALNUMBER', '2.5.4.4': 'SN', '2.5.4.42': 'GN', '1.2.840.113549.1.9.1': 'E' };
  return rdns.slice().reverse().map((rdn) => rdn.map(({ oid, value }) => (SHORT[oid] || oid) + '=' + value).join('+')).join(', ');
}

export function nameGet(rdns, oid) {
  for (const rdn of rdns) for (const a of rdn) if (a.oid === oid) return a.value;
  return null;
}

// ---------------------------------------------------------------- certificate

export class Certificate {
  constructor(bytes) {
    if (typeof bytes === 'string') bytes = pemToDer(bytes);
    else if (bytes && bytes[0] === 0x2d && bytes[1] === 0x2d) bytes = pemToDer(new TextDecoder().decode(bytes)); // PEM given as bytes
    this.raw = bytes;
    const root = decode(bytes);
    const tbs = root.child(0);
    this.tbsRaw = tbs.bytes;
    let i = 0;
    this.version = 1;
    if (tbs.child(0).isContext(0)) {
      this.version = tbs.child(0).child(0).toNumber() + 1;
      i = 1;
    }
    const serialNode = tbs.child(i++);
    this.serial = serialNode.toBigInt();
    this.serialBytes = serialNode.content; // raw two's complement content
    const sigAlg = tbs.child(i++);
    this.tbsSigAlgOid = sigAlg.child(0).toOid();
    const issuer = tbs.child(i++);
    this.issuerRaw = issuer.bytes;
    this.issuer = parseName(issuer);
    const validity = tbs.child(i++);
    this.notBefore = validity.child(0).toDate();
    this.notAfter = validity.child(1).toDate();
    const subject = tbs.child(i++);
    this.subjectRaw = subject.bytes;
    this.subject = parseName(subject);
    const spki = tbs.child(i++);
    this.spkiRaw = spki.bytes;
    const alg = spki.child(0);
    this.publicKeyAlgOid = alg.child(0).toOid();
    this.publicKeyAlgParams = alg.count > 1 ? alg.child(1) : null;
    this.publicKeyBits = spki.child(1).toBitString().bytes;
    this.extensions = new Map();
    for (; i < tbs.count; i++) {
      const n = tbs.child(i);
      if (n.isContext(3)) {
        for (const ext of n.child(0).children) {
          const oid = ext.child(0).toOid();
          let critical = false;
          let valNode = ext.child(1);
          if (valNode.isUniversal(TAG.BOOLEAN)) {
            critical = valNode.toBool();
            valNode = ext.child(2);
          }
          this.extensions.set(oid, { critical, value: valNode.content });
        }
      }
    }
    const outerAlg = root.child(1);
    this.sigAlgOid = outerAlg.child(0).toOid();
    this.signature = root.child(2).toBitString().bytes;
  }

  get subjectDnKalkan() {
    return formatNameKalkan(this.subject);
  }
  get issuerDnKalkan() {
    return formatNameKalkan(this.issuer);
  }
  get subjectCn() {
    return nameGet(this.subject, '2.5.4.3');
  }
  get issuerCn() {
    return nameGet(this.issuer, '2.5.4.3');
  }
  subjectAttr(oid) {
    return nameGet(this.subject, oid);
  }
  /** Java BigInteger.toByteArray() hex, as NCALayer reports serial numbers. */
  get serialHex() {
    return toHex(bigIntToJavaBytes(this.serial));
  }
  get pem() {
    return derToPem(this.raw, 'CERTIFICATE');
  }
  get fingerprintSha256() {
    return toHex(digest('SHA-256', this.raw));
  }

  get keyUsage() {
    const ext = this.extensions.get(OID.keyUsage);
    if (!ext) return null;
    const bs = decode(ext.value).toBitString().bytes;
    const names = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];
    const set = new Set();
    for (let bit = 0; bit < names.length; bit++) {
      const byte = bs[bit >> 3];
      if (byte !== undefined && byte & (0x80 >> (bit & 7))) set.add(names[bit]);
    }
    return set;
  }
  hasKeyUsage(name) {
    const ku = this.keyUsage;
    return !!ku && ku.has(name);
  }
  get extKeyUsage() {
    const ext = this.extensions.get(OID.extKeyUsage);
    if (!ext) return [];
    return decode(ext.value).children.map((c) => c.toOid());
  }
  get subjectKeyIdentifier() {
    const ext = this.extensions.get(OID.subjectKeyIdentifier);
    return ext ? decode(ext.value).content : null;
  }
  get authorityKeyIdentifier() {
    const ext = this.extensions.get(OID.authorityKeyIdentifier);
    if (!ext) return null;
    for (const c of decode(ext.value).children) if (c.isContext(0)) return c.content;
    return null;
  }
  get certificatePolicies() {
    const ext = this.extensions.get(OID.certificatePolicies);
    if (!ext) return [];
    return decode(ext.value).children.map((pi) => pi.child(0).toOid());
  }
  get basicConstraints() {
    const ext = this.extensions.get(OID.basicConstraints);
    if (!ext) return { ca: false };
    const seq = decode(ext.value);
    let ca = false;
    let pathLen;
    for (const c of seq.children || []) {
      if (c.isUniversal(TAG.BOOLEAN)) ca = c.toBool();
      else if (c.isUniversal(TAG.INTEGER)) pathLen = c.toNumber();
    }
    return { ca, pathLen };
  }
  get ocspUrls() {
    return this.aia(OID.ocsp);
  }
  get caIssuersUrls() {
    return this.aia(OID.caIssuers);
  }
  aia(method) {
    const ext = this.extensions.get(OID.authorityInfoAccess);
    if (!ext) return [];
    const out = [];
    for (const ad of decode(ext.value).children) {
      if (ad.child(0).toOid() === method && ad.child(1).isContext(6)) out.push(String.fromCharCode(...ad.child(1).content));
    }
    return out;
  }
  get crlUrls() {
    const ext = this.extensions.get(OID.crlDistributionPoints);
    if (!ext) return [];
    const out = [];
    const walk = (n) => {
      if (n.cls === 2 && n.tagNum === 6 && !n.constructed) out.push(String.fromCharCode(...n.content));
      else if (n.children) n.children.forEach(walk);
    };
    walk(decode(ext.value));
    return out;
  }

  isValidAt(date = new Date()) {
    return date >= this.notBefore && date <= this.notAfter;
  }

  /** Signature/key family: 'RSA' | 'GOST2004' | 'GOST2015_512' | 'GOST2015_256' | 'GOST_GT' | ... */
  get keyFamily() {
    switch (this.publicKeyAlgOid) {
      case OID.rsaEncryption: return 'RSA';
      case OID.gost34310_2004: return 'GOST2004';
      case OID.gost3410_2015_512: return 'GOST2015_512';
      case OID.gost3410_2015_256: return 'GOST2015_256';
      case OID.gostR34310_2004_GT: return 'GOST_GT';
      case OID.gostR3410_2001: return 'GOST2001';
      case OID.gost2012_256: return 'GOST2012_256';
      case OID.gost2012_512: return 'GOST2012_512';
      default: return 'UNKNOWN';
    }
  }

  /** Public key object usable for verification. */
  get publicKey() {
    if (this._pub) return this._pub;
    this._pub = parsePublicKey(this.publicKeyAlgOid, this.publicKeyAlgParams, this.publicKeyBits, this.spkiRaw);
    return this._pub;
  }

  /** Verifies this certificate's signature with the issuer's public key. */
  verifySignedBy(issuer) {
    return verifyWithPublicKey(issuer.publicKey, this.sigAlgOid, this.tbsRaw, this.signature);
  }

  isSelfIssued() {
    return equalBytes(this.issuerRaw, this.subjectRaw);
  }

  toJSON() {
    return this.pem;
  }
}

// ---------------------------------------------------------------- public keys

/** GOST key params SEQUENCE { publicKeyParamSet OID, digestParamSet OID?, encryptionParamSet OID? } */
function gostParamOids(paramsNode) {
  if (!paramsNode || !paramsNode.children) return {};
  const oids = paramsNode.children.filter((c) => c.isUniversal(TAG.OID)).map((c) => c.toOid());
  return { curveOid: oids[0], digestOid: oids[1] };
}

export function parsePublicKey(algOid, paramsNode, bits, spkiRaw) {
  if (algOid === OID.rsaEncryption) {
    const seq = decode(bits);
    return { type: 'RSA', n: seq.child(0).toBigInt(), e: seq.child(1).toBigInt(), spki: spkiRaw };
  }
  if ([OID.gost34310_2004, OID.gost3410_2015_512, OID.gost3410_2015_256, OID.gostR3410_2001, OID.gost2012_256, OID.gost2012_512, OID.gostR34310_2004_GT].includes(algOid)) {
    const { curveOid, digestOid } = gostParamOids(paramsNode);
    let curve;
    if (curveOid) curve = curveByOid(curveOid);
    else if (algOid === OID.gost3410_2015_512 || algOid === OID.gost2012_512) curve = curveByOid('1.2.398.3.10.1.1.2.2.1');
    else curve = curveByOid('1.2.398.3.10.1.1.1.1.1');
    // key bits: OCTET STRING (x || y), some encoders omit the OCTET STRING wrapper
    let pointBytes = bits;
    if (bits.length === 80 && bits[0] === 0x06 && bits[1] === 0x02 && bits[9] === 0x45 && bits[10] === 0x43) {
      // legacy Tumar CSP PUBLICKEYBLOB (NCA 1.0 "GT" keys): 16-byte header + x_LE || y_LE
      pointBytes = bits.subarray(16);
    } else {
      try {
        const n = decode(bits);
        if (n.isUniversal(TAG.OCTET_STRING)) pointBytes = n.content;
      } catch {
        /* raw point */
      }
    }
    const Q = decodePublicPoint(curve, pointBytes);
    return { type: 'GOST', algOid, curve, curveOid, digestOid, Q, spki: spkiRaw };
  }
  return { type: 'UNKNOWN', algOid, spki: spkiRaw };
}

// ---------------------------------------------------------------- RSA (public operations)

const DIGEST_INFO_PREFIX = {
  'SHA-1': '3021300906052b0e03021a05000414',
  'SHA-256': '3031300d060960864801650304020105000420',
  'SHA-384': '3041300d060960864801650304020205000430',
  'SHA-512': '3051300d060960864801650304020305000440',
};

export function digestInfo(hashName, hash) {
  const prefix = DIGEST_INFO_PREFIX[hashName];
  if (!prefix) throw new Error('No DigestInfo for ' + hashName);
  const p = new Uint8Array(prefix.length / 2);
  for (let i = 0; i < p.length; i++) p[i] = parseInt(prefix.substr(i * 2, 2), 16);
  return concat(p, hash);
}

export function rsaVerifyPkcs1(pub, hashName, hash, sig) {
  const k = Math.ceil(pub.n.toString(16).length / 2);
  if (sig.length !== k) return false;
  const m = modPow(bytesToBigInt(sig), pub.e, pub.n);
  const em = new Uint8Array(k);
  let hex = m.toString(16).padStart(k * 2, '0');
  for (let i = 0; i < k; i++) em[i] = parseInt(hex.substr(i * 2, 2), 16);
  const t = digestInfo(hashName, hash);
  if (em[0] !== 0 || em[1] !== 1) return false;
  const psEnd = k - t.length - 1;
  if (psEnd < 10) return false;
  for (let i = 2; i < psEnd; i++) if (em[i] !== 0xff) return false;
  if (em[psEnd] !== 0) return false;
  return equalBytes(em.subarray(psEnd + 1), t);
}

/** Verify `sig` over `data` using signature algorithm OID and the given public key object. */
export function verifyWithPublicKey(pub, sigAlgOid, data, sig) {
  const alg = SIG_ALGS[sigAlgOid];
  if (!alg) throw new Error('Unsupported signature algorithm ' + sigAlgOid);
  if (alg.family === 'RSA') {
    if (pub.type !== 'RSA') return false;
    return rsaVerifyPkcs1(pub, alg.hash, digest(alg.hash, data), sig);
  }
  if (pub.type !== 'GOST') return false;
  if (gostVerify(pub.curve, pub.Q, digest(alg.hash, data), sig)) return true;
  return !!alg.alt && gostVerify(pub.curve, pub.Q, digest(alg.alt, data), sig);
}

// ---------------------------------------------------------------- PEM

export function derToPem(der, label = 'CERTIFICATE') {
  const b64 = toBase64(der);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

export function pemToDer(pem) {
  const m = /-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/.exec(pem);
  return fromBase64(m ? m[1] : pem);
}

export function parseCertificate(input) {
  return new Certificate(input);
}

export { der };
