// Full browser E2E: the unpacked extension in Chromium, a test site that speaks NCALayer protocol, the Signy
// signing window driven like a user, and independent verification of every returned signature.
//   node test/e2e/run.mjs            (HEADFUL=1 to watch)
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { launch, startServer, file } from './lib.mjs';
import { verifyXml } from '../../extension/lib/xml/xmldsig.js';
import { verifyCms, parseContentInfo, findAttr } from '../../extension/lib/cms.js';
import { parseToken } from '../../extension/lib/tsp.js';
import { Certificate, pemToDer, verifyWithPublicKey } from '../../extension/lib/x509.js';
import { fromBase64, utf8Encode, toBase64, bytesToBigInt } from '../../extension/lib/util.js';
import { digest, hashByOid } from '../../extension/lib/hash/index.js';
import { decode, der } from '../../extension/lib/asn1.js';
import { OID } from '../../extension/lib/oids.js';
import { SigningKey } from '../../extension/lib/signer.js';
import { createCms } from '../../extension/lib/cms.js';
import { parsePrivateKeyInfo } from '../../extension/lib/pkcs12.js';
import { rsaKey, makeCert, name } from '../../tools/testpki.mjs';

const PKI = file('test/fixtures/test-pki/');
const PASSWORD = 'Qwerty12';
const JJS = '/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents/Home/bin/jjs';
const tmp = mkdtempSync(join(tmpdir(), 'signy-e2e-'));
const results = [];

// ---------------------------------------------------------------- mock TSA (RFC 3161) signed by an ad-hoc test key
const tsaKey = rsaKey();
const tsaName = name([['2.5.4.3', 'SIGNY MOCK TSA'], ['2.5.4.6', 'KZ', 'p']]);
const now = new Date();
const tsaCert = makeCert({ serial: 77n, issuerName: tsaName, subjectName: tsaName, notBefore: new Date(now - 86400000), notAfter: new Date(+now + 86400000 * 365), subjectKey: tsaKey, issuerKey: tsaKey, issuerSpki: tsaKey.spki, ku: ['digitalSignature'], eku: [OID.timeStamping] });
const tsaSigner = new SigningKey({ key: parsePrivateKeyInfo(tsaKey.pkcs8), cert: tsaCert, alias: 'tsa' });
const tspRequests = [];

async function tspHandler(req, res) {
  let body;
  if (req.method === 'POST') {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    body = new Uint8Array(Buffer.concat(chunks));
  } else {
    body = fromBase64(decodeURIComponent(new URL(req.url, 'http://x').pathname.replace(/^\/tsp\/?/, '')));
  }
  const tq = decode(body);
  const mi = tq.child(1);
  const policy = tq.child(2).toOid();
  const nonce = tq.child(3).toBigInt();
  tspRequests.push({ method: req.method, hashOid: mi.child(0).child(0).toOid(), policy, imprint: mi.child(1).content });
  const tstInfo = der.seq(der.int(1), der.oid(policy), mi.bytes, der.int(BigInt(tspRequests.length)), der.generalizedTime(new Date()), der.int(nonce));
  const token = await createCms(tsaSigner, tstInfo, { attached: true, eContentType: OID.tstInfo });
  const resp = der.seq(der.seq(der.int(0)), token);
  res.writeHead(200, { 'Content-Type': 'application/timestamp-reply' });
  res.end(Buffer.from(resp));
}

// ---------------------------------------------------------------- browser
const { server, port } = await startServer({ '/tsp': tspHandler });
const { context, sw, extensionId } = await launch({ headless: !process.env.HEADFUL });
const testCaPems = ['ca-gost2015.pem', 'ca-gost2004.pem', 'ca-rsa.pem'].map((f) => readFileSync(PKI + f, 'utf8'));
await sw.evaluate(async ({ pems, tsaUrl }) => {
  const { settings = {} } = await chrome.storage.local.get('settings');
  await chrome.storage.local.set({ settings: { ...settings, extraTrustPem: pems, tsaUrl } });
}, { pems: testCaPems, tsaUrl: `http://localhost:${port}/tsp` });

const page = await context.newPage();
page.on('pageerror', (e) => console.log('[page error]', e.message));
await page.goto(`http://localhost:${port}/index.html`);
await page.waitForFunction(() => typeof window.__call === 'function');

async function interactive(message, { p12, password = PASSWORD, pick = 0, action = 'sign', expectDisabled = null }) {
  const popupP = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('signer window did not open')), 15000);
    const handler = async (p) => {
      try {
        await p.waitForURL(/\/signer\/signer\.html/, { timeout: 10000 });
        clearTimeout(timer);
        context.off('page', handler);
        resolve(p);
      } catch {
        /* not the signer */
      }
    };
    context.on('page', handler);
  });
  const resultP = page.evaluate((m) => window.__call(m), message);
  const popup = await popupP;
  popup.on('pageerror', (e) => console.log('[signer error]', e.message));
  await popup.waitForSelector('#keyCard:not([hidden]), #fileCard:not([hidden]), #fatal:not([hidden])');
  if (action === 'cancel') {
    await popup.click('#cancelBtn');
    return resultP;
  }
  if (action === 'chooseKeyStore') {
    assert.equal(await popup.isVisible('#pwForm'), false, 'no password is asked when only choosing a key store');
    await popup.setInputFiles('#fileInput', PKI + p12 + '.p12');
    return resultP;
  }
  if (p12) await popup.setInputFiles('#fileInput', PKI + p12 + '.p12');
  else await popup.waitForFunction(() => /\.p12$/.test(document.getElementById('fileName').textContent)); // preselected by the site
  await popup.fill('#password', password);
  await popup.click('#openBtn');
  if (password !== PASSWORD) {
    await popup.waitForSelector('#keyError:not([hidden])');
    const err = await popup.textContent('#keyError');
    await popup.click('#cancelBtn');
    return { cancelledAfterError: err, result: await resultP };
  }
  await popup.waitForSelector('#certList li');
  if (expectDisabled !== null) {
    const disabled = await popup.$$eval('#certList li.disabled', (l) => l.length);
    assert.equal(disabled > 0, expectDisabled, 'certificate disabled state');
    if (expectDisabled) {
      const why = await popup.textContent('#certList .why');
      await popup.click('#cancelBtn');
      return { disabledReason: why, result: await resultP };
    }
  }
  await popup.click('#signBtn');
  return resultP;
}

async function check(name, fn) {
  try {
    await fn();
    results.push([name, 'OK']);
    console.log('✔', name);
  } catch (e) {
    results.push([name, 'FAIL: ' + e.message]);
    console.log('✖', name, '\n   ', e.stack.split('\n').slice(0, 4).join('\n    '));
  }
}

const CU = 'kz.gov.pki.knca.commonUtils';
const BASICS = 'kz.gov.pki.knca.basics';
const XML = '<login><timeTicket>1694567890123</timeTicket><sessionid>e2e</sessionid></login>';
const DATA = 'Документ для подписи (E2E) ✓';

function jdkVerify(xml) {
  const f = join(tmp, 'x' + Math.random() + '.xml');
  writeFileSync(f, xml);
  const out = execFileSync(JJS, [file('test/tools/jdk-verify-xml.js'), '--', f]).toString();
  assert.match(out, /^VALID/m, out);
}

await check('commonUtils.getKeyInfo returns KeyInfo bean', async () => {
  const r = await interactive({ module: CU, method: 'getKeyInfo', args: ['PKCS12'] }, { p12: 'gost2015-individual' });
  assert.equal(r.code, '200');
  const o = r.responseObject;
  for (const k of ['alias', 'keyId', 'algorithm', 'subjectCn', 'subjectDn', 'issuerCn', 'issuerDn', 'serialNumber', 'certNotAfter', 'certNotBefore', 'authorityKeyIdentifier', 'pem']) assert.ok(o[k] !== undefined, 'missing ' + k);
  assert.equal(o.subjectCn, 'ТЕСТОВ ТЕСТ');
  assert.match(o.subjectDn, /^CN=ТЕСТОВ ТЕСТ,SURNAME=ТЕСТОВ,SERIALNUMBER=IIN123456789011,C=KZ,G=ТЕСТОВИЧ$/);
  assert.match(o.certNotAfter, /^\d{13}$/);
  const c = new Certificate(o.pem);
  assert.equal(c.serialHex, o.serialNumber);
});

for (const [p12, family] of [['gost2015-individual', 'GOST 2015'], ['gost2004-sign', 'GOST 2004'], ['rsa-sign', 'RSA']]) {
  await check(`commonUtils.signXml (${family}) produces a valid enveloped XMLDSig`, async () => {
    const r = await interactive({ module: CU, method: 'signXml', args: ['PKCS12', 'SIGNATURE', XML, '', ''] }, { p12 });
    assert.equal(r.code, '200', JSON.stringify(r));
    const v = verifyXml(r.responseObject);
    assert.ok(v.length === 1 && v[0].ok, JSON.stringify(v));
    if (family === 'RSA') jdkVerify(r.responseObject);
  });
}

await check('commonUtils.signXml AUTHENTICATION filters out a signing-only RSA key', async () => {
  const r = await interactive({ module: CU, method: 'signXml', args: ['PKCS12', 'AUTHENTICATION', XML, '', ''] }, { p12: 'rsa-sign', expectDisabled: true });
  assert.match(r.disabledReason, /аутентификации/);
  assert.deepEqual(r.result, { code: '500', message: 'action.canceled' });
});

await check('commonUtils.signXml AUTHENTICATION with an RSA auth key', async () => {
  const r = await interactive({ module: CU, method: 'signXml', args: ['PKCS12', 'AUTHENTICATION', XML, '', ''] }, { p12: 'rsa-auth' });
  assert.equal(r.code, '200');
  assert.ok(verifyXml(r.responseObject)[0].ok);
  jdkVerify(r.responseObject);
});

await check('commonUtils.signXmls signs every document', async () => {
  const r = await interactive({ module: CU, method: 'signXmls', args: ['PKCS12', 'SIGNATURE', [XML, '<doc2><a>2</a></doc2>'], '', ''] }, { p12: 'gost2015-legal' });
  assert.equal(r.code, '200');
  assert.equal(r.responseObject.length, 2);
  for (const x of r.responseObject) assert.ok(verifyXml(x)[0].ok);
});

await check('commonUtils.createCAdESFromBase64 attached CMS', async () => {
  const r = await interactive({ module: CU, method: 'createCAdESFromBase64', args: ['PKCS12', 'SIGNATURE', toBase64(utf8Encode(DATA)), true] }, { p12: 'gost2015-individual' });
  assert.equal(r.code, '200', JSON.stringify(r));
  const cms = fromBase64(r.responseObject);
  const v = verifyCms(cms);
  assert.ok(v[0].ok, JSON.stringify(v));
  assert.equal(new TextDecoder().decode(parseContentInfo(cms).eContent), DATA);
});

await check('commonUtils.createCMSSignatureFromBase64 detached + TSP (SHA-256, TSA_RSA policy)', async () => {
  const before = tspRequests.length;
  const r = await interactive({ module: CU, method: 'createCMSSignatureFromBase64', args: ['PKCS12', 'SIGNATURE', toBase64(utf8Encode(DATA)), false] }, { p12: 'rsa-sign' });
  assert.equal(r.code, '200', JSON.stringify(r));
  const cms = fromBase64(r.responseObject);
  assert.ok(verifyCms(cms, utf8Encode(DATA))[0].ok);
  const si = parseContentInfo(cms).signerInfos[0];
  const ts = findAttr(si.unsignedAttrs, OID.signatureTimeStampToken);
  assert.ok(ts, 'timestamp attribute');
  const { tstInfo } = parseToken(ts.values[0]);
  assert.equal(tstInfo.policy, OID.tsaRsaPolicy);
  assert.equal(hashByOid(tstInfo.imprintHashOid), 'SHA-256');
  assert.deepEqual([...tstInfo.imprint], [...digest('SHA-256', si.signature)]);
  assert.equal(tspRequests.length, before + 1);
  assert.equal(tspRequests[before].method, 'GET', 'Kalkan uses HTTP GET to the TSA');
  // OpenSSL independent check of the RSA CMS
  writeFileSync(join(tmp, 'd.bin'), utf8Encode(DATA));
  writeFileSync(join(tmp, 's.p7s'), cms);
  execFileSync('openssl', ['cms', '-verify', '-inform', 'DER', '-in', join(tmp, 's.p7s'), '-content', join(tmp, 'd.bin'), '-binary', '-CAfile', PKI + 'ca-rsa.pem', '-purpose', 'any', '-out', '/dev/null'], { stdio: 'pipe' });
});

await check('commonUtils.createCAdESFromBase64Hash signs a SHA-256 hash with an RSA key', async () => {
  const h = digest('SHA-256', utf8Encode(DATA));
  const r = await interactive({ module: CU, method: 'createCAdESFromBase64Hash', args: ['PKCS12', 'SIGNATURE', toBase64(h)] }, { p12: 'rsa-sign' });
  assert.equal(r.code, '200', JSON.stringify(r));
  assert.ok(verifyCms(fromBase64(r.responseObject), utf8Encode(DATA))[0].ok);
});

await check('cancel returns action.canceled (commonUtils) and empty body (basics)', async () => {
  const r1 = await interactive({ module: CU, method: 'signXml', args: ['PKCS12', 'SIGNATURE', XML, '', ''] }, { action: 'cancel' });
  assert.deepEqual(r1, { code: '500', message: 'action.canceled' });
  const r2 = await interactive({ module: BASICS, method: 'sign', args: { format: 'xml', data: XML, signingParams: {}, signerParams: { extKeyUsageOids: [OID.emailProtection] } } }, { action: 'cancel' });
  assert.deepEqual(r2, { status: true, body: {} });
});

await check('wrong password is reported in the window, not to the site', async () => {
  const r = await interactive({ module: CU, method: 'signXml', args: ['PKCS12', 'SIGNATURE', XML, '', ''] }, { p12: 'gost2015-individual', password: 'wrong' });
  assert.match(r.cancelledAfterError, /Неверный пароль/);
  assert.deepEqual(r.result, { code: '500', message: 'action.canceled' });
});

await check('basics.sign xml (auth) like eGov login', async () => {
  const r = await interactive({ module: BASICS, method: 'sign', args: { allowedStorages: ['PKCS12'], format: 'xml', data: XML, signingParams: {}, signerParams: { extKeyUsageOids: [OID.clientAuth] }, locale: 'ru' } }, { p12: 'gost2015-individual' });
  assert.equal(r.status, true, JSON.stringify(r));
  assert.equal(r.body.result.length, 1);
  assert.ok(verifyXml(r.body.result[0])[0].ok);
});

await check('basics.sign cms detached + TSP returns PEM CMS with GOST 2015 timestamp profile', async () => {
  const before = tspRequests.length;
  const r = await interactive({ module: BASICS, method: 'sign', args: { format: 'cms', data: toBase64(utf8Encode(DATA)), signingParams: { decode: true, encapsulate: false, tsaProfile: {} }, signerParams: { extKeyUsageOids: [OID.emailProtection] }, locale: 'kk' } }, { p12: 'gost2015-individual' });
  assert.equal(r.status, true, JSON.stringify(r));
  const pem = r.body.result[0];
  assert.match(pem, /^-----BEGIN CMS-----\n/);
  const cms = pemToDer(pem);
  assert.ok(verifyCms(cms, utf8Encode(DATA))[0].ok);
  assert.equal(tspRequests[before].policy, OID.tsaGost2015Policy);
  assert.equal(hashByOid(tspRequests[before].hashOid), 'GOST3411-2015-512');
});

await check('basics.sign cms multi-document (array data)', async () => {
  const docs = ['документ 1', 'документ 2', 'документ 3'];
  const r = await interactive({ module: BASICS, method: 'sign', args: { format: 'cms', data: docs.map((d) => toBase64(utf8Encode(d))), signingParams: { decode: true, encapsulate: true }, signerParams: { extKeyUsageOids: [OID.emailProtection] } } }, { p12: 'gost2004-sign' });
  assert.equal(r.status, true, JSON.stringify(r));
  assert.equal(r.body.result.length, 3);
  r.body.result.forEach((pem, i) => {
    const cms = pemToDer(pem);
    assert.ok(verifyCms(cms)[0].ok);
    assert.equal(new TextDecoder().decode(parseContentInfo(cms).eContent), docs[i]);
  });
});

await check('basics.sign raw + outputCert', async () => {
  const r = await interactive({ module: BASICS, method: 'sign', args: { format: 'raw', data: toBase64(utf8Encode(DATA)), signingParams: { decode: true, outputCert: true }, signerParams: { extKeyUsageOids: [OID.emailProtection] } } }, { p12: 'gost2015-individual' });
  assert.equal(r.status, true, JSON.stringify(r));
  const cert = new Certificate(r.body.result.certificate);
  const sig = fromBase64(r.body.result.signatures[0]);
  assert.ok(verifyWithPublicKey(cert.publicKey, OID.gost3411_2015_with_gost3410_2015_512, utf8Encode(DATA), sig));
});

await check('basics.signerParams.iin mismatch disables the certificate', async () => {
  const r = await interactive({ module: BASICS, method: 'sign', args: { format: 'xml', data: XML, signingParams: {}, signerParams: { extKeyUsageOids: [OID.emailProtection], iin: '999999999999' } } }, { p12: 'gost2015-individual', expectDisabled: true });
  assert.match(r.disabledReason, /ИИН/);
});

await check('basics default chain (NCA RK only) rejects a non-NCA certificate when no extra CA is trusted', async () => {
  await sw.evaluate(async () => {
    const { settings } = await chrome.storage.local.get('settings');
    await chrome.storage.local.set({ settings: { ...settings, extraTrustPem: [] } });
  });
  try {
    const r = await interactive({ module: BASICS, method: 'sign', args: { format: 'xml', data: XML, signingParams: {}, signerParams: { extKeyUsageOids: [OID.emailProtection] } } }, { p12: 'gost2015-individual', expectDisabled: true });
    assert.match(r.disabledReason, /цепочку/);
    // with chain: [] chain building is skipped (NCALayer test mode)
    const r2 = await interactive({ module: BASICS, method: 'sign', args: { format: 'xml', data: XML, signingParams: {}, signerParams: { extKeyUsageOids: [OID.emailProtection], chain: [] } } }, { p12: 'gost2015-individual' });
    assert.equal(r2.status, true);
  } finally {
    await sw.evaluate(async (pems) => {
      const { settings } = await chrome.storage.local.get('settings');
      await chrome.storage.local.set({ settings: { ...settings, extraTrustPem: pems } });
    }, testCaPems);
  }
});

const APPLET = 'kz.gov.pki.knca.applet.Applet';

await check('legacy Applet: old MainApplet calls fail like on NCALayer 1.4, without a window', async () => {
  const r = await page.evaluate(() => window.__call({ method: 'getKeys', args: ['PKCS12', '/tmp/k.p12', '', 'SIGN'] }));
  assert.deepEqual(r, { errorCode: 'java.lang.NoSuchMethodException. Method: getKeys' });
  const t = await page.evaluate((m) => window.__call({ module: m, method: 'getTryCount', uuid: 'tc' }), APPLET);
  assert.deepEqual(t, { result: -1, errorCode: 'NONE', uuid: 'tc' });
});

await check('legacy Applet: browseKeyStore -> signXml with the chosen key (RSA), like old eGov pages', async () => {
  const b = await interactive({ module: APPLET, method: 'browseKeyStore', args: ['PKCS12', 'P12', ''], uuid: 'b1' }, { p12: 'rsa-sign', action: 'chooseKeyStore' });
  assert.equal(b.errorCode, 'NONE', JSON.stringify(b));
  assert.equal(b.uuid, 'b1');
  assert.match(b.result, /^signy-file:[0-9a-f]+\/rsa-sign\.p12$/);
  const r = await interactive({ method: 'signXml', args: ['PKCS12', b.result, 'SIGN', XML], uuid: 's1' }, { p12: null });
  assert.equal(r.errorCode, 'NONE', JSON.stringify(r).slice(0, 300));
  assert.equal(r.uuid, 's1');
  assert.ok(r.secondResult, 'key alias');
  assert.ok(r.result.startsWith('<?xml version="1.0" encoding="UTF-8" standalone="no"?><login>'), r.result.slice(0, 80));
  assert.ok(verifyXml(r.result)[0].ok);
  jdkVerify(r.result);
});

await check('legacy Applet: GOST 2015 keys cannot be used by the old API; cancel returns SIGN_CANCEL', async () => {
  const r = await interactive({ module: APPLET, method: 'signXml', args: ['PKCS12', '', 'ALL', XML], uuid: 's2' }, { p12: 'gost2015-individual', expectDisabled: true });
  assert.match(r.disabledReason, /устаревший интерфейс/);
  assert.deepEqual(r.result, { errorCode: 'SIGN_CANCEL', uuid: 's2' });
  const c = await interactive({ module: APPLET, method: 'browseKeyStore', args: ['PKCS12', 'P12', ''], uuid: 'b2' }, { action: 'cancel' });
  assert.deepEqual(c, { errorCode: 'NONE', uuid: 'b2' });
});

await check('legacy Applet: signXml with a GOST 2004 key', async () => {
  const r = await interactive({ module: APPLET, method: 'signXml', args: ['PKCS12', '', 'SIGN', XML] }, { p12: 'gost2004-sign' });
  assert.equal(r.errorCode, 'NONE', JSON.stringify(r).slice(0, 300));
  assert.ok(verifyXml(r.result)[0].ok);
});

await check('two tabs can connect at the same time', async () => {
  const p2 = await context.newPage();
  await p2.goto(`http://localhost:${port}/index.html`);
  await p2.waitForFunction(() => typeof window.__call === 'function');
  const a = await p2.evaluate(() => window.__call({ module: 'kz.gov.pki.knca.commonUtils', method: 'getActiveTokens' }));
  assert.equal(a.code, '200');
  await p2.close();
});

console.log('\n' + results.map(([n, s]) => `${s === 'OK' ? '✔' : '✖'} ${n}${s === 'OK' ? '' : ' — ' + s}`).join('\n'));
const failed = results.filter(([, s]) => s !== 'OK').length;
console.log(`\n${results.length - failed}/${results.length} E2E checks passed`);
await context.close();
server.close();
process.exit(failed ? 1 : 0);
