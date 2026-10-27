// XML-DSig creation compatible with Kalkan XMLUtil.createXmlSignature() (Apache Santuario 3.0.2 formatting),
// plus a verifier used for self-checks and tests.
import { parseXml, serialize, xmlDeclaration, Element, Text, XmlError } from './dom.js';
import { canonicalize } from './c14n.js';
import { evaluateXPathElement } from './xpath.js';
import { OID } from '../oids.js';
import { digest } from '../hash/index.js';
import { toBase64, fromBase64, utf8Encode, equalBytes } from '../util.js';
import { Certificate, verifyWithPublicKey } from '../x509.js';

export const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';
export const ALG = {
  C14N: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
  C14N_WITH_COMMENTS: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
  EXC_C14N: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  EXC_C14N_WITH_COMMENTS: 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
  ENVELOPED: 'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
};

/** Kalkan mapping: certificate signature algorithm -> XML signature/digest URIs. */
const XML_ALGS = {
  [OID.sha1WithRSA]: { sig: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha1', dig: 'http://www.w3.org/2001/04/xmldsig-more#sha1', hash: 'SHA-1' },
  [OID.sha256WithRSA]: { sig: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', dig: 'http://www.w3.org/2001/04/xmlenc#sha256', hash: 'SHA-256' },
  [OID.gost34311_95_with_gost34310_2004]: { sig: 'http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311', dig: 'http://www.w3.org/2001/04/xmldsig-more#gost34311', hash: 'GOST34311' },
  [OID.gost3411_2015_with_gost3410_2015_512]: {
    sig: 'urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512',
    dig: 'urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512',
    hash: 'GOST3411-2015-512',
  },
};

const SIG_URI_INFO = {
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': { family: 'RSA', hash: 'SHA-1' },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha1': { family: 'RSA', hash: 'SHA-1' },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': { family: 'RSA', hash: 'SHA-256' },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': { family: 'RSA', hash: 'SHA-512' },
  'http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311': { family: 'GOST', hash: 'GOST34311' },
  'urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512': { family: 'GOST', hash: 'GOST3411-2015-512' },
};
const DIG_URI_HASH = {
  'http://www.w3.org/2000/09/xmldsig#sha1': 'SHA-1',
  'http://www.w3.org/2001/04/xmldsig-more#sha1': 'SHA-1',
  'http://www.w3.org/2001/04/xmlenc#sha256': 'SHA-256',
  'http://www.w3.org/2001/04/xmlenc#sha512': 'SHA-512',
  'http://www.w3.org/2001/04/xmldsig-more#gost34311': 'GOST34311',
  'urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512': 'GOST3411-2015-512',
};

export class XmlSignError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

export function xmlAlgorithmsFor(cert) {
  const a = XML_ALGS[cert.sigAlgOid];
  if (!a) throw new XmlSignError('UNKNOWN_ALGORITHM', 'Incorrect algorithm: ' + cert.sigAlgOid);
  return a;
}

/**
 * Certificates the legacy Applet module (knca_applet SignatureUtil.signXml) can sign with: it only knows RSA-SHA1,
 * RSA-SHA256 and treats everything else as GOST 34.310-2004, so GOST 2015 keys fail there.
 */
export const LEGACY_APPLET_XML_ALGS = [OID.sha1WithRSA, OID.sha256WithRSA, OID.gost34311_95_with_gost34310_2004];

/** java.util.Base64.getMimeEncoder(): 76-char lines separated by CRLF. */
export function mimeBase64(bytes) {
  const b = toBase64(bytes);
  const lines = b.match(/.{1,76}/g) || [''];
  return lines.join('\r\n');
}

function ds(local) {
  const el = new Element('ds:' + local);
  el.ns = DS_NS;
  return el;
}

function nl(el) {
  el.appendChild(new Text('\n'));
}

function algEl(local, uri) {
  const el = ds(local);
  el.setAttribute('Algorithm', uri);
  return el;
}

/**
 * Build the <ds:Signature> skeleton the way Santuario does (line breaks as separate text nodes).
 * Returns { sig, signedInfo, digestValue, signatureValue }.
 */
function buildSignature({ c14nUri, sigUri, digUri, refUri, transforms }) {
  const sig = ds('Signature');
  sig.declareNs('ds', DS_NS);
  nl(sig);
  const signedInfo = ds('SignedInfo');
  nl(signedInfo);
  signedInfo.appendChild(algEl('CanonicalizationMethod', c14nUri));
  nl(signedInfo);
  signedInfo.appendChild(algEl('SignatureMethod', sigUri));
  nl(signedInfo);
  const ref = ds('Reference');
  ref.setAttribute('URI', refUri);
  nl(ref);
  const tr = ds('Transforms');
  nl(tr);
  for (const t of transforms) {
    tr.appendChild(algEl('Transform', t));
    nl(tr);
  }
  ref.appendChild(tr);
  nl(ref);
  ref.appendChild(algEl('DigestMethod', digUri));
  nl(ref);
  const digestValue = ds('DigestValue');
  ref.appendChild(digestValue);
  nl(ref);
  signedInfo.appendChild(ref);
  nl(signedInfo);
  sig.appendChild(signedInfo);
  nl(sig);
  const signatureValue = ds('SignatureValue');
  sig.appendChild(signatureValue);
  nl(sig);
  return { sig, signedInfo, digestValue, signatureValue };
}

function addKeyInfo(sig, cert) {
  const keyInfo = ds('KeyInfo');
  nl(keyInfo);
  const x509Data = ds('X509Data');
  nl(x509Data);
  const x509Cert = ds('X509Certificate');
  x509Cert.appendChild(new Text('\n' + mimeBase64(cert.raw) + '\n'));
  x509Data.appendChild(x509Cert);
  nl(x509Data);
  keyInfo.appendChild(x509Data);
  nl(keyInfo);
  sig.appendChild(keyInfo);
  nl(sig);
}

function setSignatureValue(el, bytes) {
  let v = mimeBase64(bytes);
  if (v.length > 76) v = '\n' + v + '\n';
  el.children = [];
  el.appendChild(new Text(v));
}

/**
 * Sign an XML document like NCALayer (commonUtils.signXml / basics xml).
 * With `legacyApplet` it follows the old Applet module instead (whole document only, RSA / GOST 2004 keys, and the
 * result is serialized by a default Transformer, i.e. with an XML declaration).
 * @param {string} xml
 * @param {SigningKey} signer
 * @param {object} opts { tbsElementXPath, signatureParentElementXPath, legacyApplet }
 */
export async function signXml(xml, signer, { tbsElementXPath = '', signatureParentElementXPath = '', legacyApplet = false } = {}) {
  if (legacyApplet) {
    if (!LEGACY_APPLET_XML_ALGS.includes(signer.cert.sigAlgOid)) throw new XmlSignError('UNKNOWN_ALGORITHM', 'Incorrect algorithm: ' + signer.cert.sigAlgOid);
    tbsElementXPath = '';
    signatureParentElementXPath = '';
  }
  const wholeDoc = !tbsElementXPath;
  if (!wholeDoc && signatureParentElementXPath && signatureParentElementXPath.toLowerCase() === tbsElementXPath.toLowerCase()) {
    throw new XmlSignError('CREATE_XML_SIGNATURE_CONSTRAINT', 'При подписи элемента XML, элемент подписи не может быть родительским элементом подписи.');
  }
  let doc;
  try {
    doc = parseXml(xml);
  } catch (e) {
    throw new XmlSignError('UNABLE_TO_PARSE_XML', 'Не удалось разобрать XML: ' + e.message);
  }
  const cert = signer.cert;
  const alg = xmlAlgorithmsFor(cert);
  const root = doc.documentElement;

  if (wholeDoc) {
    const parts = buildSignature({ c14nUri: ALG.C14N, sigUri: alg.sig, digUri: alg.dig, refUri: '', transforms: [ALG.ENVELOPED, ALG.C14N_WITH_COMMENTS] });
    root.appendChild(parts.sig);
    // Reference digest: document node-set without comments (URI=""), minus this Signature (enveloped)
    const refC14n = canonicalize(doc, { exclusive: false, withComments: false, exclude: (n) => n === parts.sig });
    parts.digestValue.appendChild(new Text(mimeBase64(digest(alg.hash, utf8Encode(refC14n)))));
    addKeyInfo(parts.sig, cert);
    const siC14n = canonicalize(parts.signedInfo, { exclusive: false, withComments: false });
    setSignatureValue(parts.signatureValue, await signer.sign(alg.hash, utf8Encode(siC14n)));
    if (legacyApplet) return xmlDeclaration(doc) + serialize(doc);
    return serialize(doc);
  }

  let target;
  try {
    target = evaluateXPathElement(doc, xml, tbsElementXPath);
  } catch (e) {
    throw new XmlSignError('UNABLE_TO_PARSE_XML', 'Ошибка XPath: ' + e.message);
  }
  if (!target) throw new XmlSignError('CREATE_XML_SIGNATURE_CONSTRAINT', `Указанный для подписи элемент ${tbsElementXPath} не найден`);
  const id = target.getAttribute('Id');
  if (!id) throw new XmlSignError('CREATE_XML_SIGNATURE_CONSTRAINT', "Указанный для подписи элемент не содержит атрибут 'Id'");
  const parts = buildSignature({ c14nUri: ALG.EXC_C14N, sigUri: alg.sig, digUri: alg.dig, refUri: '#' + id, transforms: [ALG.C14N_WITH_COMMENTS] });
  // Kalkan signs while the Signature element is still detached and appends it afterwards.
  const refC14n = canonicalize(target, { exclusive: false, withComments: false });
  parts.digestValue.appendChild(new Text(mimeBase64(digest(alg.hash, utf8Encode(refC14n)))));
  addKeyInfo(parts.sig, cert);
  const siC14n = canonicalize(parts.signedInfo, { exclusive: true, withComments: false });
  setSignatureValue(parts.signatureValue, await signer.sign(alg.hash, utf8Encode(siC14n)));
  let parent = root;
  if (signatureParentElementXPath) {
    parent = evaluateXPathElement(doc, xml, signatureParentElementXPath);
    if (!parent) throw new XmlSignError('CREATE_XML_SIGNATURE_CONSTRAINT', `Элемент ${signatureParentElementXPath} не найден`);
  }
  parent.appendChild(parts.sig);
  return serialize(doc);
}

// ---------------------------------------------------------------- verification (self-check / tests)

function childEl(el, local) {
  return el.children.find((c) => c.type === 'element' && c.ns === DS_NS && c.localName === local) || null;
}

function findById(node, id) {
  if (node.type === 'element' && (node.getAttribute('Id') === id || node.getAttribute('ID') === id || node.getAttribute('id') === id)) return node;
  for (const c of node.children || []) {
    const r = findById(c, id);
    if (r) return r;
  }
  return null;
}

function allSignatures(node, out = []) {
  if (node.type === 'element' && node.ns === DS_NS && node.localName === 'Signature') out.push(node);
  for (const c of node.children || []) allSignatures(c, out);
  return out;
}

/** Verify every ds:Signature in the document. Returns [{ ok, cert, error }]. */
export function verifyXml(xml) {
  const doc = parseXml(xml);
  return allSignatures(doc).map((sig) => {
    try {
      const si = childEl(sig, 'SignedInfo');
      const c14nUri = childEl(si, 'CanonicalizationMethod').getAttribute('Algorithm');
      const sigUri = childEl(si, 'SignatureMethod').getAttribute('Algorithm');
      const info = SIG_URI_INFO[sigUri];
      if (!info) throw new Error('unsupported SignatureMethod ' + sigUri);
      const certText = childEl(childEl(childEl(sig, 'KeyInfo'), 'X509Data'), 'X509Certificate').textContent();
      const cert = new Certificate(fromBase64(certText));
      for (const ref of si.children.filter((c) => c.type === 'element' && c.localName === 'Reference')) {
        const uri = ref.getAttribute('URI');
        const transforms = childEl(ref, 'Transforms');
        const tUris = transforms ? transforms.children.filter((c) => c.type === 'element').map((t) => t.getAttribute('Algorithm')) : [];
        const digHash = DIG_URI_HASH[childEl(ref, 'DigestMethod').getAttribute('Algorithm')];
        const expected = fromBase64(childEl(ref, 'DigestValue').textContent());
        const enveloped = tUris.includes(ALG.ENVELOPED);
        const c14nT = tUris.find((u) => u !== ALG.ENVELOPED) || ALG.C14N;
        const exclusive = c14nT.startsWith(ALG.EXC_C14N);
        let target;
        if (uri === '') target = doc;
        else if (uri.startsWith('#')) target = findById(doc, uri.slice(1));
        else throw new Error('external references are not supported');
        if (!target) throw new Error('reference target not found: ' + uri);
        // same-document references exclude comments (XMLDSig 4.3.3.3)
        const c = canonicalize(target, { exclusive, withComments: false, exclude: enveloped ? (n) => n === sig : () => false });
        if (!equalBytes(digest(digHash, utf8Encode(c)), expected)) return { ok: false, cert, error: 'digest mismatch for ' + JSON.stringify(uri) };
      }
      const siC = canonicalize(si, { exclusive: c14nUri.startsWith(ALG.EXC_C14N), withComments: c14nUri.endsWith('#WithComments') });
      const sv = fromBase64(childEl(sig, 'SignatureValue').textContent());
      const sigOid = info.family === 'RSA'
        ? { 'SHA-1': OID.sha1WithRSA, 'SHA-256': OID.sha256WithRSA, 'SHA-512': OID.sha512WithRSA }[info.hash]
        : info.hash === 'GOST34311' ? OID.gost34311_95_with_gost34310_2004 : OID.gost3411_2015_with_gost3410_2015_512;
      const ok = verifyWithPublicKey(cert.publicKey, sigOid, utf8Encode(siC), sv);
      return { ok, cert, error: ok ? null : 'bad signature value' };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  });
}

export { XmlError };
