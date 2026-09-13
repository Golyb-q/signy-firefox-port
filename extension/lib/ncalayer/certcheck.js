// Certificate classification and checks performed by NCALayer before signing (X509Util.getKNCACertificateType,
// basics KeystoreStage filtering, PKIX chain validation against NCA RK certificates).
import { Certificate } from '../x509.js';
import { OID } from '../oids.js';
import { NCA_PROD, NCA_TEST } from '../ca/nca-certs.js';
import { equalBytes, fromBase64 } from '../util.js';

let prodCache = null;
let testCache = null;

export function ncaProdCerts() {
  if (!prodCache) prodCache = Object.values(NCA_PROD).map((b) => new Certificate(fromBase64(b)));
  return prodCache;
}

export function ncaTestCerts() {
  if (!testCache) testCache = Object.values(NCA_TEST).map((b) => new Certificate(fromBase64(b)));
  return testCache;
}

/** KNCACertificateType set, exactly like knca_provider_util X509Util.getKNCACertificateType(). */
export function kncaCertTypes(cert) {
  const t = new Set();
  const ku = cert.keyUsage || new Set();
  const eku = cert.extKeyUsage;
  if (ku.has('digitalSignature') && ku.has('nonRepudiation')) {
    t.add('SIGNATURE');
    if (cert.sigAlgOid === OID.gost3411_2015_with_gost3410_2015_512 || (cert.sigAlgOid === OID.sha256WithRSA && ku.has('keyAgreement'))) t.add('AUTHENTICATION');
  }
  if (ku.has('digitalSignature') && ku.has('keyEncipherment') && eku.includes(OID.clientAuth)) t.add('AUTHENTICATION');
  if (ku.has('digitalSignature') && ku.has('keyEncipherment') && eku.includes(OID.serverAuth)) t.add('SSL');
  if (cert.extensions.has(OID.ocspNoCheck) && eku.includes(OID.ocspSigning)) t.add('OCSP_RESPONSE_SIGNING');
  if (eku.includes(OID.timeStamping)) t.add('TSP_SIGNING');
  return t;
}

/** basics KeystoreStage.isObsoleteAuthType(): old keys whose EKU lacks clientAuth still count as AUTH keys. */
function isObsoleteAuthType(requested, cert) {
  if (!requested.has(OID.clientAuth)) return false;
  const ku = cert.keyUsage || new Set();
  if (cert.sigAlgOid === OID.gost3411_2015_with_gost3410_2015_512 && ku.has('keyAgreement')) return true;
  if (cert.sigAlgOid === OID.sha256WithRSA && (ku.has('keyEncipherment') || ku.has('keyAgreement'))) return true;
  return false;
}

/**
 * Build and validate a certificate path from `cert` to one of `anchors` using intermediates from `pool`.
 * Validity periods of the path are not enforced (NCALayer uses PKIXUtil.allowExpired()).
 */
export function validateChain(cert, pool, anchors) {
  const all = [...pool, ...anchors];
  const chain = [cert];
  let cur = cert;
  for (let depth = 0; depth < 10; depth++) {
    const anchor = anchors.find((a) => equalBytes(a.raw, cur.raw));
    if (anchor && depth > 0) return { ok: true, chain, anchor };
    if (depth > 0 && cur.isSelfIssued()) {
      return { ok: false, chain, error: 'Не удалось построить цепочку до доверенного центра: корневой сертификат «' + (cur.subjectCn || '?') + '» не является доверенным (не НУЦ РК)' };
    }
    const issuers = all.filter((c) => equalBytes(c.subjectRaw, cur.issuerRaw));
    let next = null;
    for (const iss of issuers) {
      let ok = false;
      try {
        ok = cur.verifySignedBy(iss);
      } catch {
        ok = false;
      }
      if (ok) {
        next = iss;
        break;
      }
    }
    if (!next) return { ok: false, chain, error: 'Не удалось построить цепочку до доверенного центра: издатель «' + (cur.issuerCn || '?') + '» не найден' };
    if (anchors.some((a) => equalBytes(a.raw, next.raw))) {
      chain.push(next);
      return { ok: true, chain, anchor: next };
    }
    if (next === cur || chain.includes(next)) return { ok: false, chain, error: 'Цикл в цепочке сертификатов' };
    chain.push(next);
    cur = next;
  }
  return { ok: false, chain, error: 'Слишком длинная цепочка сертификатов' };
}

/** 'nca' | 'nca-test' | 'extra' for a trust anchor certificate. */
export function anchorKind(anchor) {
  if (!anchor) return null;
  if (ncaProdCerts().some((c) => equalBytes(c.raw, anchor.raw))) return 'nca';
  if (ncaTestCerts().some((c) => equalBytes(c.raw, anchor.raw))) return 'nca-test';
  return 'extra';
}

/** Display-only chain check (does not affect selectability). */
export function describeChain(entry, { includeTest = false, extra = [] } = {}) {
  const r = validateChain(entry.cert, entry.chain || [], trustAnchors({ includeTest: true, extra }));
  return { ok: r.ok, kind: r.ok ? anchorKind(r.anchor) : null, testAllowed: includeTest };
}

export function trustAnchors({ includeTest = false, extra = [] } = {}) {
  return [...ncaProdCerts(), ...(includeTest ? ncaTestCerts() : []), ...extra];
}

export function parsePemList(list) {
  const out = [];
  for (const item of list || []) {
    if (typeof item !== 'string') continue;
    const parts = item.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [item];
    for (const p of parts) {
      try {
        out.push(new Certificate(p));
      } catch {
        /* ignore unparsable */
      }
    }
  }
  return out;
}

/**
 * Evaluate a key entry against basics signerParams.
 * @returns {{disabled:boolean, reasons:string[], chainOk:boolean|null}}
 */
export function basicsEntryStatus(entry, signerParams, { anchors, now = new Date() } = {}) {
  const cert = entry.cert;
  const reasons = [];
  const requested = new Set((signerParams.extKeyUsageOids || []).map(String));
  const eku = new Set(cert.extKeyUsage);
  if (isObsoleteAuthType(requested, cert)) eku.add(OID.clientAuth);
  for (const o of requested) {
    if (!eku.has(o)) {
      reasons.push('Сертификат не предназначен для запрошенной операции (' + o + ')');
      break;
    }
  }
  let chainOk = null;
  const chain = signerParams.chain;
  if (!(Array.isArray(chain) && chain.length === 0)) {
    const trust = chain === null || chain === undefined ? anchors : parsePemList(chain);
    const r = validateChain(cert, entry.chain || [], trust);
    chainOk = r.ok;
    if (!r.ok) reasons.push(r.error);
  }
  const iin = signerParams.iin || '';
  if (iin) {
    const sn = cert.subjectAttr('2.5.4.5');
    if (!sn || sn.replace('IIN', '') !== iin) reasons.push('ИИН сертификата не совпадает с требуемым');
  }
  const bin = signerParams.bin || '';
  if (bin) {
    const ou = cert.subjectAttr('2.5.4.11');
    if (!ou || ou.replace('BIN', '') !== bin) reasons.push('БИН сертификата не совпадает с требуемым');
  }
  const serial = signerParams.serialNumber || '';
  if (serial && serial.toLowerCase() !== cert.serialHex) reasons.push('Серийный номер сертификата не совпадает с требуемым');
  const expired = !cert.isValidAt(now);
  return { disabled: reasons.length > 0, reasons, chainOk, expired };
}

/** commonUtils keyType filter (SignerDialog with KNCACertificateType; unknown type -> no filter). */
export function commonUtilsEntryStatus(entry, keyType) {
  const types = kncaCertTypes(entry.cert);
  const reasons = [];
  if (keyType === 'SIGNATURE' && !types.has('SIGNATURE')) reasons.push('Ключ не предназначен для подписи');
  if (keyType === 'AUTHENTICATION' && !types.has('AUTHENTICATION')) reasons.push('Ключ не предназначен для аутентификации');
  return { disabled: reasons.length > 0, reasons, types, expired: !entry.cert.isValidAt(new Date()) };
}
