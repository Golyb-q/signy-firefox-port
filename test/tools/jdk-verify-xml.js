// Nashorn (jjs) script: verifies XML signatures with the JDK's built-in XMLDSig implementation (Apache Santuario),
// independently of our code. Usage: jjs jdk-verify-xml.js -- file.xml
var file = arguments[0];
var dbf = Java.type('javax.xml.parsers.DocumentBuilderFactory').newInstance();
dbf.setNamespaceAware(true);
var doc = dbf.newDocumentBuilder().parse(new java.io.File(file));
var DS = 'http://www.w3.org/2000/09/xmldsig#';
var fac = Java.type('javax.xml.crypto.dsig.XMLSignatureFactory').getInstance('DOM');
var KeySelector = Java.type('javax.xml.crypto.KeySelector');
var KeySelectorResult = Java.type('javax.xml.crypto.KeySelectorResult');
var X509Data = Java.type('javax.xml.crypto.dsig.keyinfo.X509Data');
var Selector = Java.extend(KeySelector, {
  select: function (keyInfo, purpose, method, context) {
    var it = keyInfo.getContent().iterator();
    while (it.hasNext()) {
      var info = it.next();
      if (info instanceof X509Data) {
        var xi = info.getContent().iterator();
        while (xi.hasNext()) {
          var o = xi.next();
          if (o instanceof java.security.cert.X509Certificate) {
            var pk = o.getPublicKey();
            return new (Java.extend(KeySelectorResult, { getKey: function () { return pk; } }))();
          }
        }
      }
    }
    throw new javax.xml.crypto.KeySelectorException('no key');
  }
});
// register Id attributes
var all = doc.getElementsByTagName('*');
var sigs = doc.getElementsByTagNameNS(DS, 'Signature');
var ok = sigs.getLength() > 0;
for (var s = 0; s < sigs.getLength(); s++) {
  var ctx = new (Java.type('javax.xml.crypto.dsig.dom.DOMValidateContext'))(new Selector(), sigs.item(s));
  for (var i = 0; i < all.getLength(); i++) {
    var el = all.item(i);
    if (el.hasAttribute('Id')) ctx.setIdAttributeNS(el, null, 'Id');
  }
  var sig = fac.unmarshalXMLSignature(ctx);
  var valid = sig.validate(ctx);
  if (!valid) {
    print('INVALID signature #' + s + ' core=' + sig.getSignatureValue().validate(ctx));
    var refs = sig.getSignedInfo().getReferences().iterator();
    while (refs.hasNext()) { var r = refs.next(); print('  ref ' + r.getURI() + ' valid=' + r.validate(ctx)); }
    ok = false;
  }
}
print(ok ? 'VALID' : 'INVALID');
