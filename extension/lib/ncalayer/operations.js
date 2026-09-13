// Turns an NCALayer request into a signing "operation" (for the confirmation UI) and executes it with a chosen
// key, producing the exact response JSON NCALayer 1.4 would send.
import { MODULE, commonResponse, basicsSuccess, basicsError, basicsFailure, appletResponse } from './protocol.js';
import { fromBase64, toBase64, utf8Encode, tryUtf8Decode } from '../util.js';
import { createCms, applyTimestamp, cmsToPem, tryParseSignedData } from '../cms.js';
import { signXml, LEGACY_APPLET_XML_ALGS } from '../xml/xmldsig.js';
import { requestTimestamp, TSA_PROFILES } from '../tsp.js';
import { nativeHashFor } from '../signer.js';
import { derToPem } from '../x509.js';
import { OID } from '../oids.js';
import { basicsEntryStatus, commonUtilsEntryStatus, trustAnchors, validateChain, describeChain } from './certcheck.js';

export class OperationError extends Error {
  constructor(message, { code = 'SIGNING_FAILURE' } = {}) {
    super(message);
    this.code = code;
  }
}

function strictBase64(s, what) {
  if (typeof s !== 'string') throw new OperationError(`${what}: ожидалась строка base64`, { code: 'INVALID_SIGNING_PARAMS' });
  const clean = s.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) throw new OperationError(`${what}: некорректный base64`, { code: 'INVALID_SIGNING_PARAMS' });
  return fromBase64(clean);
}

function describeBytes(bytes) {
  const text = tryUtf8Decode(bytes);
  const isPdf = bytes.length > 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46;
  const printable = text !== null && !isPdf && !/[\x00-\x08\x0e-\x1f]/.test(text.slice(0, 4096));
  return { bytes, text: printable ? text : null, isPdf, size: bytes.length };
}

const KEY_TYPES = new Set(['SIGNATURE', 'AUTHENTICATION']);

/**
 * Parse a request (already routed as interactive) into an operation description.
 * @param req from protocol.parseRequest
 */
export function describeOperation(req) {
  const { module, method, args, uuid, json } = req;
  const op = { module, method, uuid, items: [], keyType: null, locale: 'ru', title: '', purpose: 'sign' };

  if (module === MODULE.COMMON) {
    const a = args;
    op.storage = String(a[0] ?? '');
    const kt = String(a[1] ?? '');
    op.keyType = KEY_TYPES.has(kt) ? kt : null;
    switch (method) {
      case 'getKeyInfo':
        op.keyType = null;
        op.storage = String(a[0] ?? '');
        op.kind = 'keyInfo';
        op.purpose = 'keyInfo';
        op.title = 'Выбор ключа (передача сведений о сертификате сайту)';
        break;
      case 'signXml':
        op.kind = 'xml';
        op.title = 'Подписание XML-документа';
        op.items = [{ xml: String(a[2] ?? ''), ...describeBytes(utf8Encode(String(a[2] ?? ''))) }];
        op.xpath = { tbsElementXPath: a[3] ? String(a[3]) : '', signatureParentElementXPath: a[4] ? String(a[4]) : '' };
        break;
      case 'signXmls':
        op.kind = 'xml';
        op.multi = true;
        op.title = 'Подписание XML-документов';
        op.items = (Array.isArray(a[2]) ? a[2] : []).map((x) => ({ xml: String(x), ...describeBytes(utf8Encode(String(x))) }));
        op.xpath = { tbsElementXPath: a[3] ? String(a[3]) : '', signatureParentElementXPath: a[4] ? String(a[4]) : '' };
        break;
      case 'createCMSSignatureFromBase64':
      case 'createCAdESFromBase64':
        op.kind = 'cms';
        op.title = method === 'createCMSSignatureFromBase64' ? 'Подписание данных (CMS с меткой времени)' : 'Подписание данных (CMS)';
        op.items = [describeBytes(strictBase64(a[2], 'data'))];
        op.cms = { attached: !!a[3], digested: false, tsa: method === 'createCMSSignatureFromBase64' ? TSA_PROFILES.commonUtils : null, requireNcaChain: method === 'createCAdESFromBase64' };
        break;
      case 'createCMSSignatureFromFile':
      case 'createCAdESFromFile':
        op.kind = 'cms';
        op.fromFile = String(a[2] ?? '');
        op.title = 'Подписание файла (CMS)';
        op.cms = { attached: !!a[3], digested: false, tsa: method === 'createCMSSignatureFromFile' ? TSA_PROFILES.commonUtils : null, requireNcaChain: method === 'createCAdESFromFile' };
        break;
      case 'createCAdESFromBase64Hash':
        op.kind = 'cms';
        op.title = 'Подписание хэша документа (CMS)';
        op.items = [{ ...describeBytes(strictBase64(a[2], 'hash')), isHash: true, text: null }];
        op.cms = { attached: false, digested: true, tsa: null, requireNcaChain: true };
        break;
      case 'applyCAdEST':
        op.kind = 'applyTsp';
        op.title = 'Добавление метки времени к подписи';
        op.items = [{ ...describeBytes(strictBase64(a[2], 'cms')), text: null, isCms: true }];
        op.cms = { tsa: TSA_PROFILES.commonUtils, requireNcaChain: true };
        break;
      case 'showFileChooser':
        op.kind = 'chooseFile';
        op.purpose = 'file';
        op.title = 'Выбор файла';
        op.fileExtension = String(a[0] ?? '');
        break;
      default:
        throw new OperationError('Unsupported method ' + method);
    }
    return op;
  }

  if (module === MODULE.BASICS) {
    const a = args;
    op.locale = a.locale === 'ru' || a.locale === 'kk' || a.locale === 'en' ? a.locale : 'kk';
    op.allowedStorages = Array.isArray(a.allowedStorages) ? a.allowedStorages.map(String) : null;
    if (typeof a.logo === 'string' && a.logo.length < 50000) op.logo = a.logo;
    const format = a.format;
    const sp = a.signingParams;
    if (!sp || typeof sp !== 'object') throw new OperationError('signingParams is required', { code: 'GENERAL_ERROR' });
    const decode = sp.decode === true;
    const data = Array.isArray(a.data) ? a.data.map(String) : [a.data === undefined ? undefined : String(a.data)];
    if (data.some((d) => d === undefined)) throw new OperationError('JSONObject["data"] not found.', { code: 'GENERAL_ERROR' });
    const signer = a.signerParams;
    if (!signer || typeof signer !== 'object' || !Array.isArray(signer.extKeyUsageOids)) throw new OperationError('signerParams.extKeyUsageOids is required', { code: 'GENERAL_ERROR' });
    op.signerParams = {
      extKeyUsageOids: signer.extKeyUsageOids.map(String),
      chain: Array.isArray(signer.chain) ? signer.chain.map(String) : null,
      iin: signer.iin ? String(signer.iin) : '',
      bin: signer.bin ? String(signer.bin) : '',
      serialNumber: signer.serialNumber ? String(signer.serialNumber) : '',
    };
    if (op.signerParams.extKeyUsageOids.includes(OID.clientAuth) && !op.signerParams.extKeyUsageOids.includes(OID.emailProtection)) op.purpose = 'auth';
    const toBytes = (d) => (decode ? strictBase64(d, 'data') : utf8Encode(d));
    if (format === 'xml') {
      op.kind = 'xml';
      op.multi = data.length > 1 || Array.isArray(a.data);
      op.items = data.map((x) => ({ xml: x, ...describeBytes(utf8Encode(x)) }));
      op.xmlParams = { allowExpired: sp.allowExpired === true, allowRevoked: sp.allowRevoked === true };
      op.title = op.purpose === 'auth' ? 'Вход на сайт (подписание XML)' : 'Подписание XML';
    } else if (format === 'cms') {
      op.kind = 'cms';
      op.multi = Array.isArray(a.data);
      op.items = data.map((d) => ({ ...describeBytes(toBytes(d)), isHash: sp.digested === true }));
      op.cms = {
        attached: sp.encapsulate !== false,
        digested: sp.digested === true,
        tsa: sp.tsaProfile && typeof sp.tsaProfile === 'object' ? TSA_PROFILES.basics : null,
        allowRevoked: sp.allowRevoked === true,
        pem: true,
      };
      op.title = op.purpose === 'auth' ? 'Аутентификация (CMS)' : 'Подписание данных (CMS)';
    } else if (format === 'raw') {
      op.kind = 'raw';
      op.multi = Array.isArray(a.data);
      op.items = data.map((d) => describeBytes(toBytes(d)));
      op.raw = { outputCert: sp.outputCert === true };
      op.title = 'Подписание данных (простая подпись)';
    } else {
      throw new OperationError('Invalid signing parameters provided.', { code: 'INVALID_SIGNING_PARAMS' });
    }
    return op;
  }

  if (module === MODULE.APPLET) {
    // kz.gov.pki.knca.applet.Applet (routed by protocol.routeRequest; arguments are strings or null)
    const a = Array.isArray(args) ? args : [];
    switch (method) {
      case 'showFileChooser':
        op.kind = 'chooseFile';
        op.purpose = 'file';
        op.title = 'Выбор файла';
        op.fileExtension = a[0] === null ? '' : String(a[0]);
        break;
      case 'browseKeyStore': {
        op.kind = 'chooseKeyStore';
        op.purpose = 'file';
        op.title = 'Выбор хранилища ключей';
        op.storage = String(a[0]);
        const ext = a[1] === null ? '' : String(a[1]);
        op.fileExtension = ext === 'KEYSTORE' && op.storage === 'PKCS12' ? 'P12' : ext === 'KEYSTORE' && op.storage === 'JKS' ? 'JKS' : ext;
        break;
      }
      case 'signXml': {
        // SignerDialog(storage, container, keyType, data): AUTH/INAUTH, SIGN/INSIGN, anything else = all keys
        op.kind = 'xml';
        op.title = 'Подписание XML-документа';
        op.storage = String(a[0]);
        op.container = a[1] === null ? '' : String(a[1]);
        const kt = String(a[2]).toUpperCase();
        op.keyType = kt === 'AUTH' || kt === 'INAUTH' ? 'AUTHENTICATION' : kt === 'SIGN' || kt === 'INSIGN' ? 'SIGNATURE' : null;
        if (op.keyType === 'AUTHENTICATION') op.purpose = 'auth';
        if (typeof a[3] !== 'string') throw new OperationError('XML-документ не передан', { code: 'SIGN_COMMON' });
        op.items = [{ xml: a[3], ...describeBytes(utf8Encode(a[3])) }];
        break;
      }
      default:
        throw new OperationError('Unsupported method ' + method);
    }
    return op;
  }
  throw new OperationError('Unsupported module ' + module);
}

const LEGACY_ALG_REASON = 'Сайт использует устаревший интерфейс NCALayer (applet), который подписывает только ключами RSA и ГОСТ 34.310-2004; этот ключ (например, ГОСТ 34.10-2015) для него не подходит';

/** Which key entries are selectable for this operation. */
export function entryStatus(op, entry, { includeTestCa = false, extraAnchors = [] } = {}) {
  const anchors = trustAnchors({ includeTest: includeTestCa, extra: extraAnchors });
  const chainInfo = describeChain(entry, { includeTest: includeTestCa, extra: extraAnchors });
  if (op.module === MODULE.BASICS) return { ...basicsEntryStatus(entry, op.signerParams, { anchors }), chainInfo };
  const st = commonUtilsEntryStatus(entry, op.keyType);
  if (op.module === MODULE.APPLET && op.kind === 'xml' && !LEGACY_APPLET_XML_ALGS.includes(entry.cert.sigAlgOid)) {
    st.reasons.push(LEGACY_ALG_REASON);
    st.disabled = true;
  }
  if (op.cms && op.cms.requireNcaChain) {
    // commonUtils CAdES methods use getSigningEntityDefaultChained() -> path must lead to NCA RK
    const r = validateChain(entry.cert, entry.chain || [], anchors);
    if (!r.ok) st.reasons.push(r.error);
    st.disabled = st.reasons.length > 0;
  }
  st.chainInfo = chainInfo;
  return st;
}

/** commonUtils KeyInfo bean (getKeyInfo response). */
export function keyInfoObject(entry) {
  const c = entry.cert;
  let authorityKeyIdentifier;
  const aki = c.authorityKeyIdentifier;
  if (aki) authorityKeyIdentifier = [...aki].map((b) => b.toString(16).padStart(2, '0')).join('');
  const ski = c.subjectKeyIdentifier;
  return {
    alias: entry.alias,
    keyId: ski ? [...ski].map((b) => b.toString(16).padStart(2, '0')).join('') : undefined,
    algorithm: entry.key.type === 'RSA' ? 'RSA' : entry.cert.keyFamily === 'GOST2004' ? 'ECGOST34310' : 'ECGOST3410-2015',
    subjectCn: c.subjectCn,
    subjectDn: c.subjectDnKalkan,
    issuerCn: c.issuerCn,
    issuerDn: c.issuerDnKalkan,
    serialNumber: c.serialHex,
    certNotAfter: String(c.notAfter.getTime()),
    certNotBefore: String(c.notBefore.getTime()),
    authorityKeyIdentifier,
    pem: c.pem,
  };
}

/**
 * Execute the operation with the chosen key.
 * @param {object} op from describeOperation
 * @param {SigningKey} signer
 * @param {object} env { fetchImpl, tsaUrl, readFile(path)->Uint8Array, onProgress(text) }
 * @returns {Promise<string>} NCALayer response JSON
 */
export async function executeOperation(op, signer, env = {}) {
  const progress = env.onProgress || (() => {});
  const ts = (profile) => (sigValue) => {
    progress('Получение метки времени (TSP)…');
    return requestTimestamp(sigValue, { url: env.tsaUrl, hash: profile.hash, policy: profile.policy, fetchImpl: env.fetchImpl });
  };

  if (op.module === MODULE.COMMON) {
    const ok = (responseObject) => commonResponse('200', { responseObject, uuid: op.uuid });
    switch (op.kind) {
      case 'keyInfo':
        return ok(keyInfoObject({ alias: signer.alias, key: signer.key, cert: signer.cert }));
      case 'xml': {
        const out = [];
        for (const it of op.items) out.push(await signXml(it.xml, signer, op.xpath));
        return ok(op.multi ? out : out[0]);
      }
      case 'cms': {
        let data = op.items[0] && op.items[0].bytes;
        if (op.fromFile) {
          if (!env.readFile) throw new OperationError('file.not_found');
          data = await env.readFile(op.fromFile);
          if (!data) throw new OperationError('file.not_found');
        }
        const cms = await createCms(signer, data, { attached: op.cms.attached, digested: op.cms.digested, timestamp: op.cms.tsa ? ts(op.cms.tsa) : null });
        return ok(toBase64(cms));
      }
      case 'applyTsp': {
        const cms = await applyTimestamp(op.items[0].bytes, signer.cert, ts(op.cms.tsa));
        return ok(toBase64(cms));
      }
      default:
        throw new OperationError('unsupported operation');
    }
  }

  if (op.module === MODULE.BASICS) {
    if (op.kind === 'xml') {
      const out = [];
      for (const it of op.items) out.push(await signXml(it.xml, signer, {}));
      return basicsSuccess({ result: out });
    }
    if (op.kind === 'cms') {
      const out = [];
      for (const it of op.items) {
        const cms = await createCms(signer, it.bytes, { attached: op.cms.attached, digested: op.cms.digested, timestamp: op.cms.tsa ? ts(op.cms.tsa) : null });
        out.push(cmsToPem(cms));
      }
      return basicsSuccess({ result: out });
    }
    if (op.kind === 'raw') {
      const hash = nativeHashFor(signer.key);
      const sigs = [];
      for (const it of op.items) sigs.push(toBase64(await signer.sign(hash, it.bytes)));
      if (op.raw.outputCert) return basicsSuccess({ result: { signatures: sigs, certificate: derToPem(signer.cert.raw) } });
      return basicsSuccess({ result: sigs.length === 1 ? sigs[0] : sigs });
    }
  }

  if (op.module === MODULE.APPLET && op.kind === 'xml') {
    // SignerDialog: result = signed XML, secondResult = key alias
    const signed = await signXml(op.items[0].xml, signer, { legacyApplet: true });
    return appletResponse('NONE', signed, signer.alias, op.uuid);
  }
  throw new OperationError('unsupported operation');
}

/** Response to a file / key store chooser: commonUtils ResponseMessage or applet ResultWrapper with the path. */
export function chosenPathResponse(op, path) {
  if (op.module === MODULE.APPLET) return appletResponse('NONE', path, null, op.uuid);
  return commonResponse('200', { responseObject: path, uuid: op.uuid });
}

/** Converts an exception into the module-specific error response. */
export function failureResponse(op, err) {
  const msg = err && err.message ? err.message : String(err);
  if (op.module === MODULE.COMMON) return commonResponse('500', { message: msg, uuid: op.uuid });
  if (op.module === MODULE.BASICS) {
    if (err && err.code && err.code !== 'SIGNING_FAILURE') {
      if (err.code === 'GENERAL_ERROR') return basicsFailure('GENERAL_ERROR', msg);
      return basicsFailure(err.code, msg);
    }
    return basicsFailure('SIGNING_FAILURE', msg);
  }
  if (op.module === MODULE.APPLET && op.method === 'signXml') {
    return appletResponse(err && err.code === 'UNABLE_TO_PARSE_XML' ? 'XML_PARSE_EXCEPTION' : 'SIGN_COMMON', null, null, op.uuid);
  }
  return appletResponse('COMMON', null, null, op.uuid);
}

export { tryParseSignedData };
