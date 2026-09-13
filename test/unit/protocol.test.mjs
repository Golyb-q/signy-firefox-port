// NCALayer 1.4 protocol emulation: routing and exact response formats (legacy Applet module in particular).
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseRequest, routeRequest, cancelResponse, appletResponse, orgJsonQuote, MODULE, MODULE_NOT_FOUND } from '../../extension/lib/ncalayer/protocol.js';
import { describeOperation, failureResponse, chosenPathResponse } from '../../extension/lib/ncalayer/operations.js';

const route = (o) => routeRequest(parseRequest(typeof o === 'string' ? o : JSON.stringify(o)));
const immediate = (o) => {
  const r = route(o);
  assert.equal(r.kind, 'immediate', JSON.stringify(r));
  return r.response;
};

test('org.json quoting and ResultWrapper key order (java.util.HashMap)', () => {
  assert.equal(orgJsonQuote('</a> "q" \\ \n\t\u0085\u2028\u00a0'), '"<\\/a> \\"q\\" \\\\ \\n\\t\\u0085\\u2028\u00a0"');
  const r = appletResponse('NONE', '<a>x</a>', 'alias', 'u-1');
  assert.equal(r, '{"result":"<a>x<\\/a>","errorCode":"NONE","secondResult":"alias","uuid":"u-1"}');
  assert.deepEqual(JSON.parse(r), { result: '<a>x</a>', errorCode: 'NONE', secondResult: 'alias', uuid: 'u-1' });
  assert.equal(appletResponse('NONE', -1), '{"result":-1,"errorCode":"NONE"}');
  assert.equal(appletResponse('SIGN_CANCEL', null, null, ''), '{"errorCode":"SIGN_CANCEL"}');
});

test('requests without "module" go to the legacy Applet module; unknown modules are not found', () => {
  assert.equal(parseRequest('{"method":"x"}').module, MODULE.APPLET);
  assert.equal(immediate({ module: '', method: 'x' }), MODULE_NOT_FOUND);
  assert.equal(immediate({ module: 'kz.example', method: 'x' }), MODULE_NOT_FOUND);
});

test('old MainApplet API is not reachable in NCALayer 1.4 (NoSuchMethodException, no uuid)', () => {
  for (const [method, args] of [
    ['getKeys', ['PKCS12', '/k.p12', '', 'SIGN']],
    ['getNotAfter', ['PKCS12', '/k.p12', 'alias', '']],
    ['getSubjectDN', ['PKCS12', '/k.p12', 'alias', '']],
    ['createCMSSignature', ['PKCS12', '/k.p12', 'alias', '', 'data', true]],
    ['signPlainData', ['PKCS12', '/k.p12', 'alias', '', 'data']],
    ['signXml', ['PKCS12', '/k.p12', 'alias', '', '<a/>']],
    ['signXmlByElementId', ['PKCS12', '/k.p12', 'a', '', '<a/>', 'id', '', '']],
    ['setLocale', ['ru']],
  ]) {
    assert.equal(immediate({ method, args, uuid: 'u' }), `{"errorCode":"java.lang.NoSuchMethodException. Method: ${method}"}`);
  }
  assert.equal(immediate({ method: 'signXml', args: ['PKCS12', '', 'SIGN', '<a/>'], class: 'kz.gov.pki.knca.applet.MainApplet' }), '{"errorCode":"java.lang.NoSuchMethodException. Method: signXml"}');
  assert.equal(immediate({ args: [] }), '{"errorCode":"org.json.JSONException: JSONObject[\\"method\\"] not found.. Method: "}');
});

test('Applet argument checks mirror Method.invoke', () => {
  assert.equal(immediate({ method: 'signXml', args: ['PKCS12', '', 5, '<a/>'] }), '{"errorCode":"java.lang.IllegalArgumentException: argument type mismatch. Method: signXml"}');
  assert.equal(immediate({ method: 'signXml', args: ['PKCS12', '', null, '<a/>'] }), '{"errorCode":"java.lang.reflect.InvocationTargetException. Method: signXml"}');
  assert.equal(immediate({ method: 'signXml', args: ['NOPE', '', 'SIGN', '<a/>'], uuid: 'u' }), '{"errorCode":"UNKNOWN_STORAGE","uuid":"u"}');
  assert.equal(immediate({ method: 'browseKeyStore', args: [null, 'P12', ''] }), '{"errorCode":"UNKNOWN_STORAGE"}');
});

test('Applet non-interactive methods', () => {
  assert.equal(immediate({ method: 'getTryCount', uuid: 'u' }), '{"result":-1,"errorCode":"NONE","uuid":"u"}');
  assert.equal(immediate({ method: 'setPassword' }), '{"result":false,"errorCode":"NONE"}');
  assert.equal(immediate({ method: 'setPassword', args: ['title'] }), '{"result":false,"errorCode":"NONE"}');
  assert.equal(immediate({ method: 'loadSlotList', args: ['AKKaztokenStore'] }), '{"errorCode":"EMPTY_SLOT"}');
  assert.equal(immediate({ method: 'genExt', args: ['2.5.29.17'] }), '{"result":"E","errorCode":"NONE"}');
  assert.equal(immediate({ method: 'genExt', args: ['1.3.6.1.5.5.7.48.1.5'] }), '{"result":"BQA=","errorCode":"NONE"}');
  assert.equal(immediate({ method: 'genExt', args: ['2.5.29.15'] }), '{"errorCode":"GENEXTENSION_CANCEL"}');
  // key issuance and token maintenance are never performed
  assert.equal(immediate({ method: 'genKeyPairAndGetPKCS10', args: ['PKCS12', '/tmp', 'pw', ['CN'], ['x'], [1], 'RSA', '', ''] }), '{"errorCode":"GENKEY_COMMON"}');
  assert.equal(immediate({ method: 'setX509CertToKeyStore', args: ['PKCS12', '/k.p12', 'pw', 'cert'] }), '{"errorCode":"SETCERT_COMMON"}');
  assert.equal(immediate({ method: 'changePassword', args: ['PKCS12', '/k.p12', 'a', 'b'] }), '{"errorCode":"CHANGEPASS_COMMON"}');
  assert.equal(immediate({ method: 'deleteEntry', args: ['PKCS12', '/k.p12', 'a'] }), '{"errorCode":"UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION"}');
  assert.equal(immediate({ method: 'resetStorage', args: ['AKJaCartaStore', 'slot'] }), '{"errorCode":"COMMON"}');
});

test('Applet interactive methods and their cancel responses', () => {
  const sx = route({ method: 'signXml', args: ['PKCS12', 'signy-file:ab/key.p12', 'SIGN', '<a/>'], uuid: 'u1' });
  assert.equal(sx.kind, 'interactive');
  assert.equal(sx.cancel, '{"errorCode":"SIGN_CANCEL","uuid":"u1"}');
  assert.equal(route({ method: 'browseKeyStore', args: ['PKCS12', 'P12', ''] }).cancel, '{"errorCode":"NONE"}');
  assert.equal(route({ method: 'browseKeyStore', args: ['AKKaztokenStore', 'P12', ''] }).cancel, '{"errorCode":"TOKEN_CHOOSE_CANCEL"}');
  assert.equal(route({ method: 'showFileChooser', args: ['ALL', ''], uuid: 'u' }).cancel, '{"errorCode":"NONE","uuid":"u"}');
  assert.equal(cancelResponse(MODULE.COMMON, 'signXml', 'u'), '{"code":"500","message":"action.canceled","uuid":"u"}');
});

test('Applet operations: key type mapping, chooser paths, failures', () => {
  const op = describeOperation(parseRequest(JSON.stringify({ method: 'signXml', args: ['PKCS12', 'signy-file:ab/key.p12', 'insign', '<a/>'], uuid: 'u' })));
  assert.equal(op.kind, 'xml');
  assert.equal(op.keyType, 'SIGNATURE');
  assert.equal(op.container, 'signy-file:ab/key.p12');
  assert.equal(describeOperation(parseRequest('{"method":"signXml","args":["PKCS12","","AUTH","<a/>"]}')).keyType, 'AUTHENTICATION');
  assert.equal(describeOperation(parseRequest('{"method":"signXml","args":["PKCS12","","other","<a/>"]}')).keyType, null);
  const ks = describeOperation(parseRequest('{"method":"browseKeyStore","args":["PKCS12","KEYSTORE",""]}'));
  assert.equal(ks.kind, 'chooseKeyStore');
  assert.equal(ks.fileExtension, 'P12');
  assert.equal(chosenPathResponse(ks, 'signy-file:ab/key.p12'), '{"result":"signy-file:ab/key.p12","errorCode":"NONE"}');
  assert.equal(failureResponse(op, Object.assign(new Error('x'), { code: 'UNABLE_TO_PARSE_XML' })), '{"errorCode":"XML_PARSE_EXCEPTION","uuid":"u"}');
  assert.equal(failureResponse(op, new Error('x')), '{"errorCode":"SIGN_COMMON","uuid":"u"}');
});
