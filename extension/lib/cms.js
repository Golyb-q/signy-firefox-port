// CMS SignedData (RFC 5652) creation compatible with Kalkan CMSUtil.createCAdES(), parsing and verification.
import { decode, der, tlv, TAG } from './asn1.js';
import { OID, SIG_ALGS, HASH_OIDS } from './oids.js';
import { HASH, digest } from './hash/index.js';
import { Certificate, verifyWithPublicKey, derToPem } from './x509.js';
import { concat, equalBytes, toBase64 } from './util.js';

export class CmsError extends Error {}

const algId = (oid) => der.seq(der.oid(oid), der.null());

function attribute(oid, ...values) {
  return der.seq(der.oid(oid), der.set(...values));
}

/** ESS signingCertificateV2 with default hash (SHA-256) and no issuerSerial - as Kalkan does. */
function signingCertificateV2(cert) {
  const certHash = digest('SHA-256', cert.raw);
  return attribute(OID.signingCertificateV2, der.seq(der.seq(der.seq(der.octet(certHash)))));
}

// ---------------------------------------------------------------- parsing

export function parseContentInfo(bytes) {
  const ci = decode(bytes);
  const type = ci.child(0).toOid();
  if (type !== OID.signedData) throw new CmsError('Not a CMS SignedData (' + type + ')');
  return parseSignedDataNode(ci.child(1).child(0));
}

export function parseSignedDataNode(sd) {
  let i = 0;
  const version = sd.child(i++).toNumber();
  const digestAlgs = sd.child(i++).children.map((a) => ({ oid: a.child(0).toOid(), raw: a.bytes }));
  const eci = sd.child(i++);
  const eContentType = eci.child(0).toOid();
  let eContent = null;
  if (eci.count > 1) eContent = eci.child(1).child(0).toOctets();
  const certificates = [];
  const crls = [];
  for (; i < sd.count; i++) {
    const n = sd.child(i);
    if (n.isContext(0)) {
      for (const c of n.children) {
        if (c.isUniversal(TAG.SEQUENCE)) {
          const raw = new Uint8Array(c.bytes);
          let cert = null;
          try {
            cert = new Certificate(raw);
          } catch {
            /* keep raw only */
          }
          certificates.push({ raw, cert });
        }
      }
    } else if (n.isContext(1)) {
      for (const c of n.children) crls.push(new Uint8Array(c.bytes));
    } else if (n.isUniversal(TAG.SET)) {
      break;
    }
  }
  const signerInfos = sd.child(sd.count - 1).children.map(parseSignerInfo);
  return { version, digestAlgs, eContentType, eContent, certificates, crls, signerInfos };
}

function parseSignerInfo(si) {
  let i = 0;
  const version = si.child(i++).toNumber();
  const sidNode = si.child(i++);
  const sid = {};
  if (sidNode.isUniversal(TAG.SEQUENCE)) {
    sid.issuerRaw = new Uint8Array(sidNode.child(0).bytes);
    sid.serial = sidNode.child(1).toBigInt();
  } else if (sidNode.isContext(0)) {
    sid.ski = new Uint8Array(sidNode.content);
  }
  const digestAlgOid = si.child(i++).child(0).toOid();
  let signedAttrs = null;
  let signedAttrsRaw = null;
  if (si.child(i).isContext(0)) {
    const n = si.child(i++);
    signedAttrsRaw = new Uint8Array(n.bytes);
    signedAttrs = parseAttributes(n);
  }
  const sigAlgOid = si.child(i++).child(0).toOid();
  const signature = new Uint8Array(si.child(i++).content);
  let unsignedAttrs = null;
  if (i < si.count && si.child(i).isContext(1)) unsignedAttrs = parseAttributes(si.child(i));
  return { version, sid, digestAlgOid, signedAttrs, signedAttrsRaw, sigAlgOid, signature, unsignedAttrs, raw: new Uint8Array(si.bytes) };
}

function parseAttributes(node) {
  const out = [];
  for (const a of node.children) out.push({ oid: a.child(0).toOid(), values: a.child(1).children.map((v) => new Uint8Array(v.bytes)), raw: new Uint8Array(a.bytes) });
  return out;
}

export function findAttr(attrs, oid) {
  return attrs ? attrs.find((a) => a.oid === oid) : null;
}

/** Tries to parse bytes as CMS SignedData; returns null if it is not one (Kalkan co-signing detection). */
export function tryParseSignedData(bytes) {
  try {
    if (!bytes || bytes.length < 16 || bytes[0] !== 0x30) return null;
    const parsed = parseContentInfo(bytes);
    if (!parsed.signerInfos.length) return null;
    return parsed;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- building

function signedDataVersion() {
  return 1;
}

function encodeSignerInfo({ issuerRaw, serial, digestOid, signedAttrsSetContent, sigAlgOid, signature, unsignedAttrs }) {
  return der.seq(
    der.int(1),
    der.seq(issuerRaw, der.int(serial)),
    algId(digestOid),
    tlv(2, true, 0, signedAttrsSetContent),
    algId(sigAlgOid),
    der.octet(signature),
    unsignedAttrs && unsignedAttrs.length ? tlv(2, true, 1, concat(...[...unsignedAttrs].sort(cmpBytes))) : null,
  );
}

function cmpBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

/** Encode the list of signed attributes as DER SET content (sorted). */
function encodeAttrSetContent(attrs) {
  return concat(...[...attrs].sort(cmpBytes));
}

/**
 * Create a CMS SignedData like Kalkan CMSUtil.createCAdES(signingEntity, data, attached, isHash).
 * @param {SigningKey} signer
 * @param {Uint8Array} data - content, or a pre-computed hash when `digested`
 * @param {object} opts { attached=true, digested=false, signingTime=new Date(), timestamp: async (signatureValue)=>tokenDer }
 */
export async function createCms(signer, data, { attached = true, digested = false, signingTime = new Date(), timestamp = null, eContentType = OID.data } = {}) {
  const cert = signer.cert;
  const hashName = signer.certHashName;
  const digestOid = (SIG_ALGS[cert.sigAlgOid] && SIG_ALGS[cert.sigAlgOid].digestOid) || HASH[hashName].oid;
  let content = data;
  let existing = eContentType === OID.data ? tryParseSignedData(data) : null;
  if (existing) {
    if (!existing.eContent) throw new CmsError('CMS_NO_ENCAPSULATED_DATA: в подписываемом CMS нет данных для совместной подписи');
    content = existing.eContent;
  }
  const messageDigest = digested && !existing ? data : digest(hashName, content);

  const signedAttrs = [
    attribute(OID.contentType, der.oid(eContentType)),
    attribute(OID.signingTime, der.time(signingTime)),
    attribute(OID.messageDigest, der.octet(messageDigest)),
    signingCertificateV2(cert),
  ];
  const setContent = encodeAttrSetContent(signedAttrs);
  const toBeSigned = tlv(0, true, TAG.SET, setContent); // DER SET OF (explicit SET tag for signing)
  const signature = await signer.sign(hashName, toBeSigned);

  let unsigned = null;
  if (timestamp) {
    const token = await timestamp(signature);
    unsigned = [attribute(OID.signatureTimeStampToken, token)];
  }
  const signerInfo = encodeSignerInfo({
    issuerRaw: cert.issuerRaw,
    serial: cert.serial,
    digestOid,
    signedAttrsSetContent: setContent,
    sigAlgOid: cert.sigAlgOid,
    signature,
    unsignedAttrs: unsigned,
  });

  const digestAlgs = [algId(digestOid)];
  const certs = [cert.raw];
  const signerInfos = [];
  if (existing) {
    for (const d of existing.digestAlgs) if (!digestAlgs.some((x) => equalBytes(x, algId(d.oid)))) digestAlgs.push(algId(d.oid));
    for (const c of existing.certificates) if (!certs.some((x) => equalBytes(x, c.raw))) certs.push(c.raw);
    for (const si of existing.signerInfos) signerInfos.push(si.raw);
  }
  signerInfos.push(signerInfo);

  const encapContent = attached ? der.seq(der.oid(eContentType), der.explicit(0, der.octet(content))) : der.seq(der.oid(eContentType));
  const signedData = der.seq(
    der.int(eContentType === OID.data ? signedDataVersion() : 3),
    der.set(...digestAlgs),
    encapContent,
    tlv(2, true, 0, concat(...certs)),
    der.setUnsorted(...signerInfos),
  );
  return der.seq(der.oid(OID.signedData), der.explicit(0, signedData));
}

/** Replace unsigned attributes of the signer (matched by certificate) with a timestamp token (Kalkan applyCAdEST). */
export async function applyTimestamp(cmsBytes, cert, timestamp) {
  const ci = decode(cmsBytes);
  const sd = ci.child(1).child(0);
  const parsed = parseSignedDataNode(sd);
  const target = parsed.signerInfos.find((si) => si.sid.serial === cert.serial && si.sid.issuerRaw && equalBytes(si.sid.issuerRaw, cert.issuerRaw));
  if (!target) throw new CmsError('Подпись владельца выбранного сертификата не найдена в CMS');
  const token = await timestamp(target.signature);
  const siNode = decode(target.raw);
  const kids = siNode.children.filter((c) => !c.isContext(1)).map((c) => c.bytes);
  const newSi = der.seq(...kids, tlv(2, true, 1, attribute(OID.signatureTimeStampToken, token)));
  // rebuild SignedData with replaced signer info
  const parts = sd.children.slice(0, sd.count - 1).map((c) => c.bytes);
  const sis = parsed.signerInfos.map((si) => (si === target ? newSi : si.raw));
  const newSd = der.seq(...parts, der.setUnsorted(...sis));
  return der.seq(der.oid(OID.signedData), der.explicit(0, newSd));
}

// ---------------------------------------------------------------- verification

/**
 * Verify all signer infos. Returns array of { ok, cert, signingTime, error }.
 * @param detachedContent content for detached signatures
 */
export function verifyCms(cmsBytes, detachedContent = null) {
  const p = parseContentInfo(cmsBytes);
  const content = p.eContent || detachedContent;
  return p.signerInfos.map((si) => {
    try {
      const cert = findSignerCert(p.certificates, si);
      if (!cert) return { ok: false, error: 'signer certificate not found' };
      const hashName = HASH_OIDS[si.digestAlgOid];
      if (!hashName) return { ok: false, cert, error: 'unsupported digest ' + si.digestAlgOid };
      let ok;
      let signingTime = null;
      if (si.signedAttrs) {
        const md = findAttr(si.signedAttrs, OID.messageDigest);
        if (!md) return { ok: false, cert, error: 'messageDigest missing' };
        const mdValue = decode(md.values[0]).content;
        if (content && !equalBytes(mdValue, digest(hashName, content))) return { ok: false, cert, error: 'messageDigest mismatch' };
        const st = findAttr(si.signedAttrs, OID.signingTime);
        if (st) signingTime = decode(st.values[0]).toDate();
        const tbs = concat(new Uint8Array([0x31]), si.signedAttrsRaw.subarray(1));
        ok = verifyBySigAlg(cert, si, tbs, hashName);
      } else {
        ok = verifyBySigAlg(cert, si, content, hashName);
      }
      return { ok, cert, signingTime, error: ok ? null : 'bad signature' };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  });
}

function verifyBySigAlg(cert, si, data, hashName) {
  const alg = SIG_ALGS[si.sigAlgOid];
  // signatureAlgorithm may be a pure key algorithm (rsaEncryption) or a combined one; use digestAlgorithm hash
  if (alg && alg.family === 'RSA' || si.sigAlgOid === OID.rsaEncryption) {
    const oid = { 'SHA-1': OID.sha1WithRSA, 'SHA-256': OID.sha256WithRSA, 'SHA-384': OID.sha384WithRSA, 'SHA-512': OID.sha512WithRSA }[hashName];
    return verifyWithPublicKey(cert.publicKey, oid, data, si.signature);
  }
  const gostSig = { GOST34311: OID.gost34311_95_with_gost34310_2004, 'GOST3411-2015-512': OID.gost3411_2015_with_gost3410_2015_512, 'GOST3411-2015-256': OID.gost3411_2015_with_gost3410_2015_256 }[hashName];
  if (!gostSig) throw new CmsError('unsupported GOST digest ' + hashName);
  return verifyWithPublicKey(cert.publicKey, gostSig, data, si.signature);
}

function findSignerCert(certs, si) {
  for (const { cert } of certs) {
    if (!cert) continue;
    if (si.sid.serial !== undefined && cert.serial === si.sid.serial && equalBytes(cert.issuerRaw, si.sid.issuerRaw)) return cert;
    if (si.sid.ski && cert.subjectKeyIdentifier && equalBytes(cert.subjectKeyIdentifier, si.sid.ski)) return cert;
  }
  return null;
}

/** PEM rendering as produced by Kalkan PEMWriter for CMSSignedData ("-----BEGIN CMS-----"). */
export function cmsToPem(cmsBytes) {
  return derToPem(cmsBytes, 'CMS');
}

export function cmsToBase64(cmsBytes) {
  return toBase64(cmsBytes);
}
