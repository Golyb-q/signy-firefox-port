// NCALayer 1.4 WebSocket protocol emulation: request routing and response formats.
// Reverse-engineered from NCALayer 1.4 (NCAWebSocket 0.4.3, NCALayerCommonBundle 0.3.4, knca_applet 0.4.13,
// NCALayerServices 0.8.1) and cross-checked with public docs (pkigovkz/sdkinfo, kaztoken.kz/mobile-docs).
// This module is DOM-free so it can run in the service worker and in extension pages.

export const MODULE = {
  COMMON: 'kz.gov.pki.knca.commonUtils',
  BASICS: 'kz.gov.pki.knca.basics',
  APPLET: 'kz.gov.pki.knca.applet.Applet',
  ACCESSORY: 'kz.gov.pki.ncalayerservices.accessory',
};

export const NCALAYER_VERSION = '1.4';

// ------------------------------------------------------------------ response builders

/** commonUtils ResponseMessage bean: {code, message?, responseObject?} (+ uuid echo) */
export function commonResponse(code, { message, responseObject, uuid } = {}) {
  const o = { code: String(code) };
  if (message !== undefined && message !== null) o.message = message;
  if (responseObject !== undefined && responseObject !== null) o.responseObject = responseObject;
  if (uuid) o.uuid = uuid;
  return JSON.stringify(o);
}

/** basics CommonResponse bean */
export function basicsSuccess(body) {
  return JSON.stringify({ status: true, body: body ?? {} });
}

export function basicsError(code, message, details) {
  const o = { status: false, code, message };
  if (details) o.details = details;
  return JSON.stringify(o);
}

export const BASICS_FAILURE = {
  SIGNING_FAILURE: 'Signing has failed.',
  INVALID_SIGNING_PARAMS: 'Invalid signing parameters provided.',
  CERTIFICATE_PARSING_FAILURE: 'Certificate parsing failure.',
  CSR_GENERATING_FAILURE: 'CSR generation has failed.',
  CERTIFICATE_IMPORTING_FAILURE: 'Certificate importing failure.',
  INVALID_IMPORTING_CERTIFICATE: 'Importing certificate is invalid.',
  GENERAL_ERROR: 'General error.',
  INVOCATION_ERROR: 'An invoked method threw an exception.',
};

export function basicsFailure(code, details) {
  return basicsError(code, BASICS_FAILURE[code] || code, details);
}

/** org.json JSONObject.quote(): escapes "</" as "<\/" and C1 / U+2000-U+20FF characters as \uXXXX. */
export function orgJsonQuote(s) {
  let out = '"';
  let prev = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    const code = s.charCodeAt(i);
    if (c === '\\' || c === '"') out += '\\' + c;
    else if (c === '/') out += prev === '<' ? '\\/' : '/';
    else if (c === '\b') out += '\\b';
    else if (c === '\t') out += '\\t';
    else if (c === '\n') out += '\\n';
    else if (c === '\f') out += '\\f';
    else if (c === '\r') out += '\\r';
    else if (code < 0x20 || (code >= 0x80 && code < 0xa0) || (code >= 0x2000 && code < 0x2100)) out += '\\u' + code.toString(16).padStart(4, '0');
    else out += c;
    prev = c;
  }
  return out + '"';
}

function orgJsonValue(v) {
  return typeof v === 'string' ? orgJsonQuote(v) : String(v);
}

/**
 * legacy applet ResultWrapper bean, serialized like JSONObject.wrap(bean).put("uuid", uuid).toString():
 * null properties are skipped and keys come out in java.util.HashMap order (result, errorCode, secondResult, uuid).
 */
export function appletResponse(errorCode, result, secondResult, uuid) {
  const parts = [];
  if (result !== undefined && result !== null) parts.push('"result":' + orgJsonValue(result));
  parts.push('"errorCode":' + orgJsonValue(errorCode));
  if (secondResult !== undefined && secondResult !== null) parts.push('"secondResult":' + orgJsonValue(secondResult));
  if (uuid) parts.push('"uuid":' + orgJsonValue(uuid));
  return '{' + parts.join(',') + '}';
}

/** Exception caught by KNCAAppletActivator: JSONStringer {"errorCode": e.toString() + ". Method: " + method}, no uuid. */
export function appletException(exception, method) {
  return '{"errorCode":' + orgJsonQuote(`${exception}. Method: ${method}`) + '}';
}

export const MODULE_NOT_FOUND = '{"success":false,"errorCode":"MODULE_NOT_FOUND"}';

// ------------------------------------------------------------------ method tables

// commonUtils: dispatch by method name AND number of args (reflection in NCALayerCommonActivator)
export const COMMON_METHODS = {
  getActiveTokens: { argc: 0, interactive: false },
  getKeyInfo: { argc: 1, interactive: true },
  signXml: { argc: 5, interactive: true },
  signXmls: { argc: 5, interactive: true },
  createCMSSignatureFromBase64: { argc: 4, interactive: true },
  createCMSSignatureFromFile: { argc: 4, interactive: true },
  createCAdESFromBase64: { argc: 4, interactive: true },
  createCAdESFromFile: { argc: 4, interactive: true },
  createCAdESFromBase64Hash: { argc: 3, interactive: true },
  applyCAdEST: { argc: 3, interactive: true },
  showFileChooser: { argc: 2, interactive: true },
  changeLocale: { argc: 1, interactive: false },
};

// basics: PKIExtras.sign + PKIEssentials (CSR generation / certificate import are not supported)
export const BASICS_METHODS = {
  sign: { interactive: true, cls: 'PKIExtras' },
  generateCsr: { interactive: false, cls: 'PKIEssentials' },
  importCertificate: { interactive: false, cls: 'PKIEssentials' },
};

// Legacy "Deprecated Applet" module. NCALayer 1.4 registers a single object for it, kz.gov.pki.knca.applet.Applet
// (KNCAAppletActivator), and calls its declared method with the requested name and number of arguments. The old
// MainApplet API (getKeys, createCMSSignature, signPlainData, ...) is not reachable any more: real NCALayer answers
// such calls with NoSuchMethodException, and so does Signy.
// argc -> parameter types (S = String, A = String[], I = int[]). Declared methods that make no sense over JSON
// (getProvider / setProvider, showTokenChooser(Storage), private getStorage / setTryCount) are left out and get
// NoSuchMethodException here, while NCALayer would dump the provider or fail with an access/type error.
export const APPLET_CLASS = 'kz.gov.pki.knca.applet.Applet';
export const APPLET_METHODS = {
  showFileChooser: { 2: 'SS' },
  browseKeyStore: { 3: 'SSS' },
  setPassword: { 0: '', 1: 'S' },
  loadSlotList: { 1: 'S' },
  getPublicPartInfo: { 1: 'S' },
  genExt: { 1: 'S' },
  genKeyPairAndGetPKCS10: { 9: 'SSSAAISSS' },
  setX509CertToKeyStore: { 4: 'SSSS' },
  setX509CertToKeyStoreAndChangePassword: { 5: 'SSSSS' },
  changePassword: { 4: 'SSSS' },
  signXml: { 4: 'SSSS' },
  deleteEntry: { 3: 'SSS' },
  resetStorage: { 2: 'SS' },
  getTryCount: { 0: '' },
};

/** kz.gov.pki.kalkan.Storage names accepted by Storage.get() -> isToken() */
export const KALKAN_STORAGES = {
  AKKaztokenStore: true,
  AKKZIDCardStore: true,
  AKEToken72KStore: true,
  AKEToken5110Store: true,
  AKJaCartaStore: true,
  AKAKEYStore: true,
  ABCloudServiceStore: true,
  PKCS12: false,
  JKS: false,
};

const hasOwn = (o, k) => typeof k === 'string' && Object.prototype.hasOwnProperty.call(o, k);

// Applet.genExt(): extensions edited in NCA operator dialogs (not available in Signy)
const GENEXT_DIALOG_OIDS = ['2.5.29.15', '2.5.29.37', '2.5.29.31', '2.5.29.46', '2.5.29.19', '1.3.6.1.5.5.7.1.1', '2.5.29.32'];
const OCSP_NOCHECK = '1.3.6.1.5.5.7.48.1.5';
const NPE = 'java.lang.reflect.InvocationTargetException'; // a NullPointerException inside the invoked method

// ------------------------------------------------------------------ parsing & routing

export function parseRequest(payload) {
  let json;
  try {
    json = JSON.parse(payload);
  } catch {
    return null;
  }
  if (!json || typeof json !== 'object' || Array.isArray(json)) return null;
  // NCAWebSocket: json.optString("module", "kz.gov.pki.knca.applet.Applet")
  const module = json.module === undefined || json.module === null ? MODULE.APPLET : String(json.module);
  return { json, module, method: json.method, args: json.args, uuid: typeof json.uuid === 'string' ? json.uuid : '' };
}

/** Immediate answers of the legacy Applet module; null when the call needs the signing window. */
function routeApplet(req) {
  const { json, uuid } = req;
  if (json.method === undefined || json.method === null) return appletException('org.json.JSONException: JSONObject["method"] not found.', '');
  const method = String(json.method);
  const cls = json.class === undefined || json.class === null ? '' : String(json.class);
  const argv = Array.isArray(json.args) ? json.args : [];
  const types = !cls || cls === APPLET_CLASS ? hasOwn(APPLET_METHODS, method) && APPLET_METHODS[method][argv.length] : undefined;
  if (typeof types !== 'string') return appletException('java.lang.NoSuchMethodException', method);
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i];
    const ok = v === null || (types[i] === 'S' ? typeof v === 'string' : Array.isArray(v));
    if (!ok) return appletException('java.lang.IllegalArgumentException: argument type mismatch', method);
  }
  const reply = (errorCode, result) => appletResponse(errorCode, result, null, uuid);
  const storage = argv[0];
  const known = hasOwn(KALKAN_STORAGES, storage);
  const isToken = known && KALKAN_STORAGES[storage];
  switch (method) {
    case 'getTryCount':
      return reply('NONE', -1);
    case 'setPassword':
      // password dialog for the key-issuance flow; answered as "cancelled"
      return reply('NONE', false);
    case 'loadSlotList':
      return reply('EMPTY_SLOT');
    case 'getPublicPartInfo':
      return reply('GETPUBLICPART_EXCEPTION');
    case 'genExt': {
      const oid = argv[0];
      if (oid === null) return appletException(NPE, method);
      const isOid = (o) => oid.toLowerCase() === o.toLowerCase();
      if (GENEXT_DIALOG_OIDS.some(isOid)) return reply('GENEXTENSION_CANCEL');
      if (isOid('2.5.29.17')) return reply('NONE', 'E');
      if (oid === OCSP_NOCHECK) return reply('NONE', 'BQA=');
      return appletException(NPE, method);
    }
    // key issuance / token maintenance is not supported by Signy (it never creates, modifies or formats key stores)
    case 'genKeyPairAndGetPKCS10':
      return reply(known ? 'GENKEY_COMMON' : 'UNKNOWN_STORAGE');
    case 'setX509CertToKeyStore':
    case 'setX509CertToKeyStoreAndChangePassword':
      if (argv[argv.length - 1] === null) return appletException(NPE, method);
      return reply(known ? 'SETCERT_COMMON' : 'UNKNOWN_STORAGE');
    case 'changePassword':
      return reply(known ? 'CHANGEPASS_COMMON' : 'UNKNOWN_STORAGE');
    case 'deleteEntry':
      if (!known) return reply('UNKNOWN_STORAGE');
      return reply(isToken && storage !== 'AKKZIDCardStore' ? 'CANCEL' : 'UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION');
    case 'resetStorage':
      if (!known) return reply('UNKNOWN_STORAGE');
      return reply(['AKEToken72KStore', 'AKJaCartaStore', 'AKEToken5110Store'].includes(storage) ? 'COMMON' : 'UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION');
    case 'browseKeyStore':
      if (!known) return reply('UNKNOWN_STORAGE');
      if (!isToken && argv[1] === null) return appletException(NPE, method);
      return null;
    case 'signXml':
      if (!known) return reply('UNKNOWN_STORAGE');
      if (argv[2] === null) return appletException(NPE, method); // SignerDialog: keyType.toUpperCase()
      return null;
    case 'showFileChooser':
      return null;
    default:
      return appletException('java.lang.NoSuchMethodException', method);
  }
}

/**
 * Decide how to handle a request.
 * @returns {{kind:'immediate', response:string} | {kind:'interactive', module, method, cancel?:string} | {kind:'accessory'} | {kind:'ignore'}}
 */
export function routeRequest(req, ctx = {}) {
  if (!req) return { kind: 'ignore' };
  const { module, method, args, uuid, json } = req;
  switch (module) {
    case MODULE.COMMON: {
      const argc = Array.isArray(args) ? args.length : 0;
      const m = COMMON_METHODS[method];
      if (typeof method !== 'string' || !method || !m || m.argc !== argc) {
        return { kind: 'immediate', response: commonResponse('500', { message: 'NoSuchMethodException ' + method }) };
      }
      if (method === 'getActiveTokens') return { kind: 'immediate', response: commonResponse('200', { responseObject: [], uuid }) };
      if (method === 'changeLocale') return { kind: 'immediate', response: commonResponse('200', { uuid }) };
      return { kind: 'interactive', module, method };
    }
    case MODULE.BASICS: {
      const apiVersion = json.apiVersion === undefined ? 2 : Number(json.apiVersion);
      if (apiVersion !== 2) return { kind: 'immediate', response: basicsFailure('GENERAL_ERROR', 'java.lang.IllegalArgumentException: Supported apiVersion is 2') };
      if (typeof method !== 'string') return { kind: 'immediate', response: basicsFailure('GENERAL_ERROR', 'org.json.JSONException: JSONObject["method"] not found.') };
      const m = BASICS_METHODS[method];
      const cls = typeof json.class === 'string' ? json.class : '';
      if (cls && cls !== 'PKIExtras' && cls !== 'PKIEssentials') return { kind: 'immediate', response: basicsFailure('GENERAL_ERROR', `java.lang.IllegalArgumentException: ${cls} is not found`) };
      if (!m || (cls && m.cls !== cls) || (!cls && m.cls !== 'PKIExtras')) {
        return { kind: 'immediate', response: basicsFailure('GENERAL_ERROR', `java.lang.IllegalArgumentException: ${method} is not defined in ${cls || 'PKIExtras'}`) };
      }
      if (!args || typeof args !== 'object' || Array.isArray(args)) return { kind: 'immediate', response: basicsFailure('GENERAL_ERROR', `java.lang.IllegalArgumentException: ${method} demands arguments`) };
      if (!m.interactive) return { kind: 'immediate', response: basicsFailure('GENERAL_ERROR', `Signy: метод ${method} (выпуск ключей НУЦ) не поддерживается`) };
      return { kind: 'interactive', module, method };
    }
    case MODULE.ACCESSORY: {
      // NCALayer shows its service windows; Signy opens its settings page instead.
      return { kind: 'accessory', method };
    }
    case MODULE.APPLET: {
      const response = routeApplet(req);
      if (response !== null) return { kind: 'immediate', response };
      return { kind: 'interactive', module, method: String(method), cancel: cancelResponse(module, String(method), uuid, args) };
    }
    default:
      return { kind: 'immediate', response: MODULE_NOT_FOUND };
  }
}

/**
 * Response sent when the user closes the signing window.
 * Legacy Applet: SignerDialog -> SIGN_CANCEL, TokenChooserDialog -> TOKEN_CHOOSE_CANCEL, FileChooserDialog -> no result.
 */
export function cancelResponse(module, method, uuid, args) {
  switch (module) {
    case MODULE.COMMON:
      return commonResponse('500', { message: 'action.canceled', uuid });
    case MODULE.BASICS:
      return basicsSuccess({});
    case MODULE.APPLET:
      if (method === 'signXml') return appletResponse('SIGN_CANCEL', null, null, uuid);
      if (method === 'browseKeyStore' && Array.isArray(args) && KALKAN_STORAGES[args[0]] === true) return appletResponse('TOKEN_CHOOSE_CANCEL', null, null, uuid);
      return appletResponse('NONE', null, null, uuid);
    default:
      return null;
  }
}
