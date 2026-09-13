// Cross-checks our canonicalization against libxml2 (via python lxml) when available.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { writeFileSync, readFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseXml, serialize, xmlDeclaration } from '../../extension/lib/xml/dom.js';
import { canonicalize } from '../../extension/lib/xml/c14n.js';
import { selectElement } from '../../extension/lib/xml/xpath.js';

const DOCS = [
  `<?xml version="1.0" encoding="UTF-8"?>
<!-- comment before -->
<?pi-before data?>
<root xmlns="urn:default" xmlns:a="urn:a" xmlns:b="urn:b" b:attr="2" attr="1" xml:lang="ru">
  <a:child a:x="&lt;&amp;&gt;&quot;'" y="tab&#9;nl&#10;cr&#13; sp" z='single "q"'>text &amp; more &lt;&gt; "q" 'a' &#13; end</a:child>
  <empty/>
  <!-- inner comment -->
  <![CDATA[cdata <&> content]]>
  <b:c xmlns:a="urn:a" xmlns:c="urn:c-unused"><inner xmlns=""><deep a:y="1"/></inner></b:c>
  <?inner-pi x?>
  <kaz xml:space="preserve">Қазақша мәтін 😀</kaz>
</root>
<!-- after -->`,
  `<login><timeTicket>1694567890123</timeTicket><sessionid>abc</sessionid></login>`,
  `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="urn:ws"><soap:Header/><soap:Body Id="body"><ws:req xmlns:x="urn:x" x:q="1"><ws:data Id="d1">val</ws:data></ws:req></soap:Body></soap:Envelope>`,
];

let python = null;
try {
  execFileSync('python3', ['-c', 'import lxml'], { stdio: 'ignore' });
  python = 'python3';
} catch {
  /* lxml not available */
}

function lxmlC14n(xml, { xpath = null, exclusive = false, withComments = false }) {
  const script = `
import sys, json
from lxml import etree
args = json.loads(sys.argv[1])
doc = etree.fromstring(args['xml'].encode('utf-8'), etree.XMLParser(resolve_entities=False)).getroottree()
node = doc
if args['xpath']:
    node = doc.xpath(args['xpath'], namespaces={'a':'urn:a','b':'urn:b','d':'urn:default','soap':'http://schemas.xmlsoap.org/soap/envelope/','ws':'urn:ws'})[0]
sys.stdout.write(etree.tostring(node, method='c14n', exclusive=args['exclusive'], with_comments=args['withComments']).decode('utf-8'))
`;
  return execFileSync(python, ['-c', script, JSON.stringify({ xml, xpath, exclusive, withComments })]).toString('utf-8');
}

const CASES = [
  { doc: 0, xpath: null, ours: null },
  { doc: 0, xpath: '//a:child', ours: '//a:child' },
  { doc: 0, xpath: '//b:c', ours: '//b:c' },
  { doc: 0, xpath: '//d:kaz', ours: '//*[local-name()="kaz"]' },
  { doc: 0, xpath: '//b:c/inner', ours: '//*[local-name()="inner"]' },
  { doc: 1, xpath: null, ours: null },
  { doc: 2, xpath: null, ours: null },
  { doc: 2, xpath: '//soap:Body', ours: '//*[@Id="body"]' },
  { doc: 2, xpath: '//ws:data', ours: '//*[@Id="d1"]' },
];

test('canonicalization matches libxml2 (lxml)', { skip: !python && 'python3 + lxml not available' }, () => {
  for (const c of CASES) {
    const xml = DOCS[c.doc];
    const doc = parseXml(xml);
    const node = c.ours ? selectElement(doc, c.ours, (p) => ({ a: 'urn:a', b: 'urn:b' })[p]) : doc;
    assert.ok(node, 'node found for ' + c.ours);
    for (const exclusive of [false, true]) {
      for (const withComments of [false, true]) {
        const expected = lxmlC14n(xml, { xpath: c.xpath, exclusive, withComments });
        let got = canonicalize(node, { exclusive, withComments });
        // C14N 1.0 imports xml:* attributes of ancestors into the apex of a document subset (Santuario does this,
        // libxml2's element serialization does not) - compare without the inherited attribute.
        if (c.xpath && !exclusive && node.type === 'element' && !node.attrs.some((a) => a.name === 'xml:lang')) got = got.replace(' xml:lang="ru"', '');
        assert.equal(got, expected, `doc${c.doc} ${c.xpath || 'document'} exclusive=${exclusive} comments=${withComments}`);
      }
    }
  }
});

test('C14N 1.0 subset imports xml:lang from ancestors (Santuario behaviour)', () => {
  const doc = parseXml('<r xml:lang="ru" xmlns="urn:d"><c a="1"/></r>');
  assert.equal(canonicalize(selectElement(doc, '//*[local-name()="c"]')), '<c xmlns="urn:d" a="1" xml:lang="ru"></c>');
  assert.equal(canonicalize(selectElement(doc, '//*[local-name()="c"]'), { exclusive: true }), '<c xmlns="urn:d" a="1"></c>');
});

test('serializer escapes like Xalan and round-trips', () => {
  const doc = parseXml('<a z="1" b="x&#10;y&quot;">t&amp;&#13;<![CDATA[<x>]]><e/></a>');
  const s = serialize(doc);
  assert.equal(s, '<a b="x&#10;y&quot;" z="1">t&amp;&#13;<![CDATA[<x>]]><e/></a>');
  assert.equal(canonicalize(parseXml(s)), canonicalize(doc));
});

const E = String.fromCodePoint(0x1f600);
const C1 = String.fromCharCode(0x85);
const DEL = String.fromCharCode(0x7f);
const LS = String.fromCharCode(0x2028);
const NBSP = String.fromCharCode(0xa0);
// (a CDATA section that *starts* with a supplementary character loses its brackets in Xalan - even when it holds
// markup characters, producing broken XML; Signy keeps such a section intact, so that case is not compared)
const SPECIAL = `<a b="${C1}${DEL}${E}">x${C1} ${LS}${NBSP}\t${DEL}${E}<!--${E}${C1}--><?p ${E}${C1}?><![CDATA[x${E}<&>]]></a>`;

test('serializer escapes C1 controls and supplementary characters like JDK 8 Xalan', () => {
  assert.equal(serialize(parseXml(SPECIAL)), `<a b="${C1}${DEL}&#128512;">x&#133; ${LS}${NBSP}\t&#127;&#128512;<!--${E}${C1}--><?p ${E}${C1}?><![CDATA[x${E}<&>]]></a>`);
  assert.equal(xmlDeclaration(parseXml('<a/>')), '<?xml version="1.0" encoding="UTF-8" standalone="no"?>');
  assert.equal(xmlDeclaration(parseXml('<?xml version="1.0" standalone="yes"?><a/>')), '<?xml version="1.0" encoding="UTF-8"?>');
});

const JJS = '/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents/Home/bin/jjs';

test('serializer output equals the JDK Transformer (Kalkan XMLUtil and applet SignatureUtil)', { skip: !existsSync(JJS) && 'jjs not available' }, () => {
  const tmp = mkdtempSync(join(tmpdir(), 'signy-ser-'));
  const cases = [
    ...DOCS,
    SPECIAL,
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><r a="&#9;"/>',
    // namespace declarations first, redundant ones dropped (Xalan NamespaceMappings)
    '<r z="1" a="2" xmlns:z="urn:z" xmlns="urn:d" b:x="3" xmlns:b="urn:b"/>',
    '<r xmlns="urn:d"><c xmlns="urn:d"/><c xmlns=""><e xmlns=""/></c></r>',
    '<r xmlns=""/>',
    '<r xmlns:p="urn:1"><c xmlns:p="urn:2"/><d xmlns:p="urn:1"/><a xmlns:q="urn:q"/><b xmlns:q="urn:q"/></r>',
    '<r xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></r>',
    '<p:r xmlns:p="urn:p" p:a="1" a="2"><p:c xmlns:p="urn:p2" p:a="3"/></p:r>',
  ];
  cases.forEach((xml, i) => {
    for (const mode of ['omit', 'decl']) {
      const inp = join(tmp, `in${i}.xml`);
      const out = join(tmp, `out${i}${mode}.xml`);
      writeFileSync(inp, xml);
      execFileSync(JJS, [new URL('../tools/jdk-serialize.js', import.meta.url).pathname, '--', inp, out, mode]);
      const doc = parseXml(xml);
      const mine = (mode === 'decl' ? xmlDeclaration(doc) : '') + serialize(doc);
      assert.equal(mine, readFileSync(out, 'utf8'), `case ${i} (${mode})`);
    }
  });
});

test('DOCTYPE is rejected like Kalkan', () => {
  assert.throws(() => parseXml('<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>'), /DOCTYPE/);
});
