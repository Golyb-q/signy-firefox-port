#!/usr/bin/env node
// Cross-check: signatures created by Signy are verified by the original Kalkan provider (from the NCALayer
// distribution) running in a local JVM via Nashorn. Nothing is installed; no network access is needed.
//   KALKAN_JARS=/path/kalkancrypt-0.7.8.jar:/path/kalkancrypt_xmldsig-osgi-0.5.1.jar node test/tools/kalkan-crosscheck.mjs
import { readFileSync, writeFileSync, mkdtempSync, existsSync, readdirSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parsePkcs12 } from '../../extension/lib/pkcs12.js';
import { SigningKey, nativeHashFor } from '../../extension/lib/signer.js';
import { createCms, applyTimestamp } from '../../extension/lib/cms.js';
import { signXml, LEGACY_APPLET_XML_ALGS } from '../../extension/lib/xml/xmldsig.js';
import { utf8Encode } from '../../extension/lib/util.js';
import { digest } from '../../extension/lib/hash/index.js';

const JJS = process.env.JJS || '/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents/Home/bin/jjs';
const JARS = process.env.KALKAN_JARS;
if (!JARS || !existsSync(JJS)) {
  console.log('KALKAN_JARS / jjs not available - skipping Kalkan cross-check');
  process.exit(0);
}
const root = new URL('../../', import.meta.url).pathname;
const tmp = mkdtempSync(join(tmpdir(), 'signy-kalkan-'));
const script = join(root, 'test/tools/kalkan-verify.js');
let n = 0;
let failed = 0;

function kalkan(...args) {
  try {
    const out = execFileSync(JJS, ['-cp', JARS, script, '--', ...args], { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
    return out;
  } catch (e) {
    return 'ERROR ' + (e.stderr ? e.stderr.toString() : e.message);
  }
}

function report(label, out) {
  n++;
  const ok = /RESULT VALID/.test(out);
  if (!ok) failed++;
  console.log(`${ok ? '✔' : '✖'} ${label}${ok ? '' : '\n    ' + out.trim().split('\n').join('\n    ')}`);
}

const keys = [
  ['test-pki/gost2015-individual.p12', 'Qwerty12'],
  ['test-pki/gost2004-sign.p12', 'Qwerty12'],
  ['test-pki/rsa-sign.p12', 'Qwerty12'],
  ['nca-test-keys/gokalkan/gost1.p12', 'Qwerty12'],
  ['nca-test-keys/trusty/Нового НУЦ (new oids)/ЮЛ/ПЕРВЫЙ РУКОВОДИТЕЛЬ/Действ/GOSTKNCA_aa066248efa0c931574668ca984b13c3b5170724.p12', '123456'],
  ['nca-test-keys/trusty/Нового НУЦ (new oids)/ФЛ/Действ/RSA256_68c6bc6b81b7f97a794754ce9f57d195dda4a42d.p12', '123456'],
  ['nca-test-keys/trusty/Текущий НУЦ (old oids)/ЮР ДЕЙСТВ 2/GOSTKZ_e56fe5a0899f787815adaf5d256da7a0a70c2c13.p12', '123456'],
].filter(([p]) => existsSync(join(root, 'test/fixtures', p)));

const XMLS = [
  ['login', '<login><timeTicket>1694567890123</timeTicket><sessionid>x</sessionid></login>', {}],
  ['ns+comments', '<?xml version="1.0" encoding="UTF-8"?>\n<root xmlns="urn:egov" xmlns:x="urn:x" b="2" a="1"><x:item x:k="v">Текст &amp; &lt;данные&gt;</x:item>\n  <empty/>\n<!-- c --><![CDATA[cd<>]]></root>', {}],
  ['by-id', '<root><data Id="d1"><v>1</v></data><sigs/></root>', { tbsElementXPath: "//*[@Id='d1']", signatureParentElementXPath: '/root/sigs' }],
];

let k = 0;
for (const [p, pw] of keys) {
  k++;
  const r = await parsePkcs12(new Uint8Array(readFileSync(join(root, 'test/fixtures', p))), pw);
  const s = new SigningKey(r.entries[0]);
  const tag = `${s.cert.keyFamily} ${p.split('/').pop().slice(0, 28)}`;
  // XML
  for (const [name, xml, opts] of XMLS) {
    let signed;
    try {
      signed = await signXml(xml, s, opts);
    } catch (e) {
      console.log(`  (xml ${name} not applicable for ${tag}: ${e.message})`);
      continue;
    }
    const f = join(tmp, `x${k}_${n}.xml`);
    writeFileSync(f, signed);
    report(`XML ${name} ${tag}`, kalkan('xml', f));
  }
  // legacy Applet module signXml (RSA / GOST 2004 keys only)
  if (LEGACY_APPLET_XML_ALGS.includes(s.cert.sigAlgOid)) {
    const f = join(tmp, `l${k}.xml`);
    writeFileSync(f, await signXml(XMLS[1][1], s, { legacyApplet: true }));
    report(`XML legacy-applet ${tag}`, kalkan('xml', f));
  }
  // CMS attached / detached / digested / co-signed / with (fake-free) timestamp attribute structure
  const data = utf8Encode('Документ Signy → Kalkan');
  const att = await createCms(s, data, { attached: true });
  writeFileSync(join(tmp, `c${k}.p7s`), att);
  report(`CMS attached ${tag}`, kalkan('cms', join(tmp, `c${k}.p7s`)));
  const det = await createCms(s, data, { attached: false });
  writeFileSync(join(tmp, `d${k}.p7s`), det);
  writeFileSync(join(tmp, `d${k}.bin`), data);
  report(`CMS detached ${tag}`, kalkan('cms', join(tmp, `d${k}.p7s`), join(tmp, `d${k}.bin`)));
  const dig = await createCms(s, digest(s.certHashName, data), { attached: false, digested: true });
  writeFileSync(join(tmp, `h${k}.p7s`), dig);
  report(`CMS digested ${tag}`, kalkan('cms', join(tmp, `h${k}.p7s`), join(tmp, `d${k}.bin`)));
  const co = await createCms(s, att, { attached: true });
  writeFileSync(join(tmp, `co${k}.p7s`), co);
  report(`CMS co-signed (2 signers) ${tag}`, kalkan('cms', join(tmp, `co${k}.p7s`)));
  // basics raw
  const hash = nativeHashFor(s.key);
  const sig = await s.sign(hash, data);
  writeFileSync(join(tmp, `r${k}.sig`), sig);
  writeFileSync(join(tmp, `r${k}.cer`), s.cert.raw);
  const alg = s.key.type === 'RSA' ? 'SHA256withRSA' : hash === 'GOST3411-2015-512' ? 'ECGOST3410-2015-512' : 'ECGOST34310';
  report(`raw ${alg} ${tag}`, kalkan('raw', join(tmp, `r${k}.cer`), join(tmp, `d${k}.bin`), join(tmp, `r${k}.sig`), alg));
}
console.log(`\n${n - failed}/${n} Kalkan verifications passed`);
process.exit(failed ? 1 : 0);
