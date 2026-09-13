// Nashorn (jjs) script: verifies signatures produced by Signy with the Kalkan crypto provider shipped in NCALayer
// (kalkancrypt + kalkancrypt_xmldsig). Pure cryptographic checks, no network, nothing is installed.
//   jjs -cp kalkancrypt.jar:kalkancrypt_xmldsig.jar kalkan-verify.js -- xml file.xml
//   jjs -cp ... kalkan-verify.js -- cms file.p7s [content.bin]
var Files = java.nio.file.Files;
var Paths = java.nio.file.Paths;
var Security = Java.type('java.security.Security');
var provider = new (Java.type('kz.gov.pki.kalkan.jce.provider.KalkanProvider'))();
Security.addProvider(provider);

var mode = arguments[0];
var path = arguments[1];

function readBytes(p) { return Files.readAllBytes(Paths.get(p)); }

if (mode === 'xml') {
  Java.type('kz.gov.pki.kalkan.xmldsig.KncaXS').loadXMLSecurity();
  var dbf = Java.type('javax.xml.parsers.DocumentBuilderFactory').newInstance();
  dbf.setNamespaceAware(true);
  var doc = dbf.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(readBytes(path)));
  var all = doc.getElementsByTagName('*');
  for (var i = 0; i < all.getLength(); i++) {
    var el = all.item(i);
    if (el.hasAttribute('Id')) el.setIdAttribute('Id', true);
  }
  var sigs = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature');
  var ok = sigs.getLength() > 0;
  for (var s = 0; s < sigs.getLength(); s++) {
    var sig = new (Java.type('org.apache.xml.security.signature.XMLSignature'))(sigs.item(s), '');
    var cert = sig.getKeyInfo().getX509Certificate();
    var valid = sig.checkSignatureValue(cert);
    print('signature #' + s + ' ' + cert.getSigAlgName() + ' -> ' + (valid ? 'VALID' : 'INVALID'));
    if (!valid) ok = false;
  }
  print(ok ? 'RESULT VALID' : 'RESULT INVALID');
} else if (mode === 'cms') {
  var CMSSignedData = Java.type('kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData');
  var CMSProcessableByteArray = Java.type('kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray');
  var bytes = readBytes(path);
  var cms = arguments.length > 2 ? new CMSSignedData(new CMSProcessableByteArray(readBytes(arguments[2])), bytes) : new CMSSignedData(bytes);
  var store = cms.getCertificatesAndCRLs('Collection', 'KALKAN');
  var it = cms.getSignerInfos().getSigners().iterator();
  var ok = true;
  var n = 0;
  while (it.hasNext()) {
    var signer = it.next();
    var certs = store.getCertificates(signer.getSID()).iterator();
    var cert = certs.next();
    // verify with the public key: pure cryptographic check (test certificates may be expired)
    var valid = signer.verify(cert.getPublicKey(), 'KALKAN');
    print('signer #' + (n++) + ' digest=' + signer.getDigestAlgOID() + ' enc=' + signer.getEncryptionAlgOID() + ' -> ' + (valid ? 'VALID' : 'INVALID'));
    var ua = signer.getUnsignedAttributes();
    if (ua != null && ua.get(new (Java.type('kz.gov.pki.kalkan.asn1.DERObjectIdentifier'))('1.2.840.113549.1.9.16.2.14')) != null) print('  has timestamp token');
    if (!valid) ok = false;
  }
  print(ok && n > 0 ? 'RESULT VALID' : 'RESULT INVALID');
} else if (mode === 'raw') {
  // raw <certPem> <dataFile> <sigFile> <algorithm>  (basics format=raw)
  var cf = Java.type('java.security.cert.CertificateFactory').getInstance('X.509', 'KALKAN');
  var cert = cf.generateCertificate(new java.io.ByteArrayInputStream(readBytes(path)));
  var sigAlg = arguments[4];
  var v = Java.type('java.security.Signature').getInstance(sigAlg, 'KALKAN');
  v.initVerify(cert.getPublicKey());
  v.update(readBytes(arguments[2]));
  var valid = v.verify(readBytes(arguments[3]));
  print('raw ' + sigAlg + ' -> ' + (valid ? 'VALID' : 'INVALID'));
  print(valid ? 'RESULT VALID' : 'RESULT INVALID');
} else {
  print('usage: xml <file> | cms <file> [content] | raw <cert> <data> <sig> <alg>');
}
