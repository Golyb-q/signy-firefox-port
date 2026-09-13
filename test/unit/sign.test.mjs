// End-to-end signing tests on the generated TEST PKI (tools/testpki.mjs) with independent verification
// (OpenSSL for CMS/RSA, JDK XMLDSig for XML/RSA) where the tools are available.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parsePkcs12 } from '../../extension/lib/pkcs12.js';
import { SigningKey } from '../../extension/lib/signer.js';
import { createCms, verifyCms, parseContentInfo, applyTimestamp } from '../../extension/lib/cms.js';
import { signXml, verifyXml } from '../../extension/lib/xml/xmldsig.js';
import { utf8Encode, toBase64, fromBase64 } from '../../extension/lib/util.js';
import { digest } from '../../extension/lib/hash/index.js';
import { derToPem } from '../../extension/lib/x509.js';

const PKI = new URL('../fixtures/test-pki/', import.meta.url).pathname;
const tmp = mkdtempSync(join(tmpdir(), 'signy-'));
const JJS = '/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents/Home/bin/jjs';
const hasJjs = existsSync(JJS);

async function key(id) {
  const r = await parsePkcs12(new Uint8Array(readFileSync(PKI + id + '.p12')), 'Qwerty12');
  return new SigningKey(r.entries[0]);
}

const KEYS = ['gost2015-individual', 'gost2015-legal', 'gost2004-sign', 'rsa-auth', 'rsa-sign'];

test('CMS attached/detached for all key types verifies (own verifier)', async () => {
  for (const id of KEYS) {
    const k = await key(id);
    const data = utf8Encode('Документ для подписи ' + id);
    const attached = await createCms(k, data, { attached: true });
    const r1 = verifyCms(attached);
    assert.equal(r1.length, 1);
    assert.ok(r1[0].ok, id + ' attached: ' + r1[0].error);
    const detached = await createCms(k, data, { attached: false });
    assert.equal(parseContentInfo(detached).eContent, null);
    assert.ok(verifyCms(detached, data)[0].ok, id + ' detached');
    assert.ok(!verifyCms(detached, utf8Encode('tampered'))[0].ok, id + ' tamper detection');
  }
});

test('CMS structure matches Kalkan conventions', async () => {
  const k = await key('gost2015-individual');
  const cms = parseContentInfo(await createCms(k, utf8Encode('x')));
  assert.equal(cms.version, 1);
  assert.deepEqual(cms.digestAlgs.map((d) => d.oid), ['1.2.398.3.10.1.3.3']);
  const si = cms.signerInfos[0];
  assert.equal(si.digestAlgOid, '1.2.398.3.10.1.3.3');
  assert.equal(si.sigAlgOid, '1.2.398.3.10.1.1.2.3.2'); // = certificate signature algorithm (Kalkan uses cert.getSigAlgOID())
  assert.deepEqual(si.signedAttrs.map((a) => a.oid).sort(), ['1.2.840.113549.1.9.16.2.47', '1.2.840.113549.1.9.3', '1.2.840.113549.1.9.4', '1.2.840.113549.1.9.5'].sort());
  assert.equal(si.signature.length, 128);
});

test('CMS digested mode signs a precomputed hash', async () => {
  const k = await key('gost2015-individual');
  const data = utf8Encode('hash me');
  const h = digest('GOST3411-2015-512', data);
  const cms = await createCms(k, h, { attached: false, digested: true });
  assert.ok(verifyCms(cms, data)[0].ok);
});

test('CMS co-signing (Kalkan behaviour when data is already a CMS)', async () => {
  const a = await key('gost2015-individual');
  const b = await key('rsa-sign');
  const first = await createCms(a, utf8Encode('общий документ'), { attached: true });
  const second = await createCms(b, first, { attached: true });
  const r = verifyCms(second);
  assert.equal(r.length, 2);
  assert.ok(r.every((x) => x.ok), JSON.stringify(r.map((x) => x.error)));
  const p = parseContentInfo(second);
  assert.equal(new TextDecoder().decode(p.eContent), 'общий документ');
  assert.equal(p.certificates.length, 2);
});

test('applyTimestamp adds signatureTimeStampToken to the right signer', async () => {
  const k = await key('rsa-sign');
  const cms = await createCms(k, utf8Encode('ts'));
  let seen = null;
  const fakeToken = (await createCms(k, utf8Encode('token'))).slice(); // any ContentInfo DER
  const out = await applyTimestamp(cms, k.cert, async (sigValue) => {
    seen = sigValue;
    return fakeToken;
  });
  const si = parseContentInfo(out).signerInfos[0];
  assert.ok(seen && seen.length === 256);
  assert.equal(si.unsignedAttrs[0].oid, '1.2.840.113549.1.9.16.2.14');
  assert.ok(verifyCms(out)[0].ok);
});

test('OpenSSL verifies our RSA CMS (independent check)', async () => {
  const k = await key('rsa-sign');
  const data = utf8Encode('openssl check ✓');
  const cms = await createCms(k, data, { attached: false });
  writeFileSync(join(tmp, 'd.bin'), data);
  writeFileSync(join(tmp, 's.p7s'), cms);
  const out = execFileSync('openssl', ['cms', '-verify', '-inform', 'DER', '-in', join(tmp, 's.p7s'), '-content', join(tmp, 'd.bin'), '-binary', '-CAfile', PKI + 'ca-rsa.pem', '-purpose', 'any', '-out', '/dev/null'], { stdio: ['ignore', 'pipe', 'pipe'] });
  assert.ok(true, out.toString());
});

const XMLS = [
  '<login><timeTicket>1694567890123</timeTicket></login>',
  '<?xml version="1.0" encoding="UTF-8"?>\n<root xmlns="urn:egov" xmlns:x="urn:x" b="2" a="1"><x:item x:k="v">Текст &amp; &lt;данные&gt;</x:item>\n  <empty/>\n<!-- c --></root>',
];

test('XML signatures (whole document) verify for all key types', async () => {
  for (const id of KEYS) {
    const k = await key(id);
    for (const xml of XMLS) {
      const signed = await signXml(xml, k);
      const r = verifyXml(signed);
      assert.equal(r.length, 1);
      assert.ok(r[0].ok, id + ': ' + r[0].error + '\n' + signed);
    }
  }
});

test('XML output layout matches NCALayer/Santuario', async () => {
  const k = await key('rsa-sign');
  const signed = await signXml('<login><timeTicket>1</timeTicket></login>', k);
  assert.match(signed, /^<login><timeTicket>1<\/timeTicket><ds:Signature xmlns:ds="http:\/\/www\.w3\.org\/2000\/09\/xmldsig#">\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm="http:\/\/www\.w3\.org\/TR\/2001\/REC-xml-c14n-20010315"\/>\n<ds:SignatureMethod Algorithm="http:\/\/www\.w3\.org\/2001\/04\/xmldsig-more#rsa-sha256"\/>\n<ds:Reference URI="">\n<ds:Transforms>\n<ds:Transform Algorithm="http:\/\/www\.w3\.org\/2000\/09\/xmldsig#enveloped-signature"\/>\n<ds:Transform Algorithm="http:\/\/www\.w3\.org\/TR\/2001\/REC-xml-c14n-20010315#WithComments"\/>\n<\/ds:Transforms>\n<ds:DigestMethod Algorithm="http:\/\/www\.w3\.org\/2001\/04\/xmlenc#sha256"\/>\n<ds:DigestValue>[A-Za-z0-9+\/=]{44}<\/ds:DigestValue>\n<\/ds:Reference>\n<\/ds:SignedInfo>\n<ds:SignatureValue>\n/);
  assert.ok(signed.includes('&#13;\n'), 'MIME base64 CRLF is escaped as &#13;');
  assert.ok(signed.endsWith('</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature></login>'));
});

test('XML element signature by XPath (tbsElementXPath / signatureParentElementXPath)', async () => {
  const xml = '<root><data Id="d1"><v>1</v></data><sigs/></root>';
  for (const id of ['gost2015-individual', 'rsa-sign']) {
    const k = await key(id);
    const signed = await signXml(xml, k, { tbsElementXPath: "//*[@Id='d1']", signatureParentElementXPath: '/root/sigs' });
    assert.ok(signed.includes('<sigs><ds:Signature'), signed);
    assert.ok(signed.includes('URI="#d1"'));
    assert.ok(signed.includes('xml-exc-c14n#'));
    const r = verifyXml(signed);
    assert.ok(r[0].ok, id + ': ' + r[0].error);
  }
  const k = await key('rsa-sign');
  await assert.rejects(signXml('<root><data><v/></data></root>', k, { tbsElementXPath: '/root/data' }), /Id/);
  await assert.rejects(signXml('<root/>', k, { tbsElementXPath: '/root/none' }), /не найден/);
});

test('JDK XMLDSig (Santuario) validates our RSA XML signatures', { skip: !hasJjs && 'jjs not available' }, async () => {
  const k = await key('rsa-sign');
  const cases = [
    await signXml(XMLS[0], k),
    await signXml(XMLS[1], k),
    await signXml('<root><data Id="d1"><v>1</v></data><sigs/></root>', k, { tbsElementXPath: "//*[@Id='d1']", signatureParentElementXPath: '/root/sigs' }),
  ];
  cases.forEach((signed, i) => {
    const f = join(tmp, `x${i}.xml`);
    writeFileSync(f, signed);
    const out = execFileSync(JJS, [new URL('../tools/jdk-verify-xml.js', import.meta.url).pathname, '--', f]).toString();
    assert.match(out, /VALID/, out);
    assert.doesNotMatch(out, /INVALID/, out + '\n' + signed);
  });
});

test('XML co-signing: the new signature is valid (the earlier enveloped one breaks, exactly as with Kalkan)', async () => {
  const a = await key('gost2015-individual');
  const b = await key('rsa-sign');
  const once = await signXml('<doc><v>1</v></doc>', a);
  const twice = await signXml(once, b);
  const r = verifyXml(twice);
  assert.equal(r.length, 2);
  assert.ok(r[1].ok, 'second signature');
  // the first signature is not enveloped by the second signature's transform -> it becomes invalid, same as Kalkan
});

test('legacy Applet signXml: XML declaration, RSA / GOST 2004 only, verifies', async () => {
  for (const id of ['rsa-sign', 'gost2004-sign']) {
    const k = await key(id);
    const signed = await signXml('<login><timeTicket>1</timeTicket></login>', k, { legacyApplet: true });
    assert.ok(signed.startsWith('<?xml version="1.0" encoding="UTF-8" standalone="no"?><login><timeTicket>1</timeTicket><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n<ds:SignedInfo>\n'), signed.slice(0, 200));
    assert.ok(signed.endsWith('</ds:Signature></login>'));
    assert.ok(verifyXml(signed)[0].ok, id);
  }
  const k = await key('rsa-sign');
  assert.ok((await signXml('<?xml version="1.0" standalone="yes"?><a/>', k, { legacyApplet: true })).startsWith('<?xml version="1.0" encoding="UTF-8"?><a><ds:Signature'));
  // element signing parameters do not exist in the old API
  assert.ok(verifyXml(await signXml('<root><data Id="d1"/></root>', k, { legacyApplet: true, tbsElementXPath: "//*[@Id='d1']" }))[0].ok);
  await assert.rejects(signXml('<a/>', await key('gost2015-individual'), { legacyApplet: true }), /Incorrect algorithm/);
});

test('legacy Applet signXml response carries the signed XML and the key alias', async () => {
  const { describeOperation, executeOperation } = await import('../../extension/lib/ncalayer/operations.js');
  const { parseRequest } = await import('../../extension/lib/ncalayer/protocol.js');
  const op = describeOperation(parseRequest(JSON.stringify({ method: 'signXml', args: ['PKCS12', 'signy-file:ab/rsa.p12', 'SIGN', '<doc><v>1</v></doc>'], uuid: 'u-7' })));
  const k = await key('rsa-sign');
  const raw = await executeOperation(op, k);
  assert.ok(raw.startsWith('{"result":"<?xml version=\\"1.0\\" encoding=\\"UTF-8\\" standalone=\\"no\\"?><doc><v>1<\\/v>'), raw.slice(0, 120));
  const r = JSON.parse(raw);
  assert.equal(r.errorCode, 'NONE');
  assert.equal(r.secondResult, k.alias);
  assert.equal(r.uuid, 'u-7');
  assert.ok(verifyXml(r.result)[0].ok);
});

test('signed XML is a fixed point of JDK parse + Transformer (same serialization as Kalkan / knca_applet)', { skip: !hasJjs && 'jjs not available' }, async () => {
  const k = await key('rsa-sign');
  const xml = '<r xmlns="urn:d" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" z="1" a="2"><x:i xmlns:x="urn:x" xmlns="urn:d">Текст &amp; &#128512;</x:i></r>';
  const cases = [[await signXml(xml, k), 'omit'], [await signXml(xml, k, { legacyApplet: true }), 'decl']];
  cases.forEach(([signed, mode], i) => {
    const inp = join(tmp, `fp${i}.xml`);
    const out = join(tmp, `fp${i}.out`);
    writeFileSync(inp, signed);
    execFileSync(JJS, [new URL('../tools/jdk-serialize.js', import.meta.url).pathname, '--', inp, out, mode]);
    assert.equal(readFileSync(out, 'utf8'), signed, mode);
  });
});
