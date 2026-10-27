// RFC 3161 Time-Stamp Protocol client (NCA RK TSA: http://tsp.pki.gov.kz), Kalkan TSPUtil-compatible.
import { decode, der, TAG } from './asn1.js';
import { OID } from './oids.js';
import { HASH, digest } from './hash/index.js';
import { parseContentInfo, verifyCms } from './cms.js';
import { toBase64, equalBytes, bytesToBigInt, randomBytes } from './util.js';

export const DEFAULT_TSA_URL = 'http://tsp.pki.gov.kz';

export class TspError extends Error {}

/** TSA profiles used by NCALayer modules. */
export const TSA_PROFILES = {
  // commonUtils.createCMSSignatureFromBase64 / applyCAdEST: new TSAProfile() defaults
  commonUtils: { hash: 'SHA-256', policy: OID.tsaRsaPolicy },
  // basics.sign(format=cms, tsaProfile={}): GOST 34.11-2015 512 + TSA_GOST_2015 policy
  basics: { hash: 'GOST3411-2015-512', policy: OID.tsaGost2015Policy },
};

export function buildTimeStampRequest(hashName, messageHash, policyOid, nonce) {
  return der.seq(
    der.int(1),
    der.seq(der.seq(der.oid(HASH[hashName].oid), der.null()), der.octet(messageHash)),
    policyOid ? der.oid(policyOid) : null,
    der.int(nonce),
    der.bool(true), // certReq
  );
}

function statusText(code) {
  return ['granted', 'grantedWithMods', 'rejection', 'waiting', 'revocationWarning', 'revocationNotification'][code] || 'unknown(' + code + ')';
}

/** Parse TimeStampResp; returns { token: Uint8Array, tstInfo } or throws TspError. */
export function parseTimeStampResponse(bytes) {
  const resp = decode(bytes);
  const status = resp.child(0);
  const code = status.child(0).toNumber();
  if (code !== 0 && code !== 1) {
    let text = '';
    if (status.count > 1 && status.child(1).isUniversal(TAG.SEQUENCE)) text = status.child(1).children.map((c) => c.toStr()).join('; ');
    throw new TspError(`TSA отказал: ${statusText(code)}${text ? ' — ' + text : ''}`);
  }
  if (resp.count < 2) throw new TspError('TSA не вернул метку времени');
  const token = new Uint8Array(resp.child(1).bytes);
  return { token, ...parseToken(token) };
}

export function parseToken(token) {
  const cms = parseContentInfo(token);
  if (cms.eContentType !== OID.tstInfo) throw new TspError('Неверный тип содержимого метки времени');
  const t = decode(cms.eContent);
  let i = 0;
  const version = t.child(i++).toNumber();
  const policy = t.child(i++).toOid();
  const mi = t.child(i++);
  const imprintHashOid = mi.child(0).child(0).toOid();
  const imprint = new Uint8Array(mi.child(1).content);
  const serial = t.child(i++).toBigInt();
  const genTime = t.child(i++).toDate();
  let nonce = null;
  for (; i < t.count; i++) {
    const n = t.child(i);
    if (n.isUniversal(TAG.INTEGER)) nonce = n.toBigInt();
  }
  return { cms, tstInfo: { version, policy, imprintHashOid, imprint, serial, genTime, nonce } };
}

function randomNonce() {
  const b = randomBytes(8);
  b[0] &= 0x7f;
  return bytesToBigInt(b) || 1n;
}

/**
 * Obtain a timestamp token over `data` (for CAdES-T: the SignerInfo signature value).
 * @param opts { url, hash, policy, method: 'GET'|'POST', fetchImpl }
 * @returns Promise<Uint8Array> TimeStampToken (ContentInfo DER)
 */
export async function requestTimestamp(data, { url = DEFAULT_TSA_URL, hash = 'SHA-256', policy = OID.tsaRsaPolicy, method = 'GET', fetchImpl = globalThis.fetch, verify = true } = {}) {
  const messageHash = digest(hash, data);
  const nonce = randomNonce();
  const req = buildTimeStampRequest(hash, messageHash, policy, nonce);
  const attempt = async (m) => {
    let res;
    if (m === 'POST') {
      res = await fetchImpl(url.replace(/\/?$/, '/'), { method: 'POST', headers: { 'Content-Type': 'application/timestamp-query' }, body: req, cache: 'no-store', credentials: 'omit' });
    } else {
      const u = (url.endsWith('/') ? url : url + '/') + encodeURIComponent(toBase64(req));
      res = await fetchImpl(u, { method: 'GET', cache: 'no-store', credentials: 'omit' });
    }
    if (!res.ok) throw new TspError('TSA HTTP ' + res.status);
    return new Uint8Array(await res.arrayBuffer());
  };
  let body;
  try {
    body = await attempt(method);
  } catch (e) {
    // fall back to the other transport (POST is the RFC 3161 standard, GET is what Kalkan uses)
    body = await attempt(method === 'GET' ? 'POST' : 'GET').catch(() => {
      throw new TspError('Сервис меток времени недоступен: ' + e.message);
    });
  }
  const { token, tstInfo, cms } = parseTimeStampResponse(body);
  if (!equalBytes(tstInfo.imprint, messageHash)) throw new TspError('Метка времени выдана на другие данные');
  if (tstInfo.nonce !== null && tstInfo.nonce !== nonce) throw new TspError('Неверный nonce в ответе TSA');
  if (verify) {
    const v = verifyCms(token);
    if (!v.length || !v[0].ok) throw new TspError('Подпись метки времени не прошла проверку: ' + (v[0] && v[0].error));
  }
  return token;
}
