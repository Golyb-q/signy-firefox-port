// Nashorn (jjs) script, JDK classes only: parse an XML file the way Kalkan / knca_applet do (namespace-aware,
// DOCTYPE disallowed) and serialize it back with a default identity Transformer.
//   jjs jdk-serialize.js -- in.xml out.xml omit    (Kalkan XMLUtil.getXmlString: omit-xml-declaration=yes)
//   jjs jdk-serialize.js -- in.xml out.xml decl    (knca_applet SignatureUtil.signXml: default output properties)
var Files = java.nio.file.Files;
var Paths = java.nio.file.Paths;
var f = javax.xml.parsers.DocumentBuilderFactory.newInstance();
f.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true);
f.setNamespaceAware(true);
var doc = f.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(Files.readAllBytes(Paths.get(arguments[0]))));
var t = javax.xml.transform.TransformerFactory.newInstance().newTransformer();
if (arguments[2] === 'omit') t.setOutputProperty('omit-xml-declaration', 'yes');
var sw = new java.io.StringWriter();
t.transform(new javax.xml.transform.dom.DOMSource(doc), new javax.xml.transform.stream.StreamResult(sw));
Files.write(Paths.get(arguments[1]), sw.toString().getBytes('UTF-8'));
