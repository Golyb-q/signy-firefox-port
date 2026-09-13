// Minimal namespace-aware XML 1.0 parser producing a light DOM-like tree, plus a serializer that mimics
// the JDK Transformer (Xalan) output used by NCALayer (omit-xml-declaration, attributes sorted by name as in a
// Xerces DOM, CR escaped as &#13;). No DTD support: like Kalkan (disallow-doctype-decl) a DOCTYPE is rejected.

export const XML_NS = 'http://www.w3.org/XML/1998/namespace';
export const XMLNS_NS = 'http://www.w3.org/2000/xmlns/';

export class XmlError extends Error {}

const PREDEF = { lt: '<', gt: '>', amp: '&', apos: "'", quot: '"' };

function isWs(c) {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
}

export class Node {
  constructor(type) {
    this.type = type;
    this.parent = null;
  }
}

export class Element extends Node {
  constructor(name) {
    super('element');
    this.name = name;
    const i = name.indexOf(':');
    this.prefix = i >= 0 ? name.slice(0, i) : '';
    this.localName = i >= 0 ? name.slice(i + 1) : name;
    this.ns = '';
    this.attrs = []; // {name, prefix, localName, ns, value}
    this.children = [];
    this.nsDecls = new Map(); // own declarations prefix('' = default) -> uri
  }
  getAttribute(name) {
    const a = this.attrs.find((x) => x.name === name);
    return a ? a.value : null;
  }
  getAttributeNS(ns, localName) {
    const a = this.attrs.find((x) => x.ns === ns && x.localName === localName);
    return a ? a.value : null;
  }
  setAttribute(name, value) {
    const a = this.attrs.find((x) => x.name === name);
    if (a) a.value = value;
    else {
      const i = name.indexOf(':');
      this.attrs.push({ name, prefix: i >= 0 ? name.slice(0, i) : '', localName: i >= 0 ? name.slice(i + 1) : name, ns: '', value });
    }
  }
  /** Declare a namespace on this element (adds xmlns attribute). */
  declareNs(prefix, uri) {
    this.nsDecls.set(prefix, uri);
    const name = prefix ? 'xmlns:' + prefix : 'xmlns';
    if (!this.attrs.find((a) => a.name === name)) this.attrs.push({ name, prefix: prefix ? 'xmlns' : '', localName: prefix || 'xmlns', ns: XMLNS_NS, value: uri, isNsDecl: true });
  }
  appendChild(node) {
    if (node.parent) node.parent.children.splice(node.parent.children.indexOf(node), 1);
    node.parent = this;
    this.children.push(node);
    return node;
  }
  get elementChildren() {
    return this.children.filter((c) => c.type === 'element');
  }
  /** In-scope namespaces (prefix -> uri); '' -> default namespace ('' means none). */
  inScopeNamespaces() {
    const chain = [];
    for (let e = this; e && e.type === 'element'; e = e.parent) chain.push(e);
    const m = new Map();
    for (let i = chain.length - 1; i >= 0; i--) for (const [p, u] of chain[i].nsDecls) m.set(p, u);
    return m;
  }
  lookupNamespace(prefix) {
    if (prefix === 'xml') return XML_NS;
    for (let e = this; e && e.type === 'element'; e = e.parent) if (e.nsDecls.has(prefix)) return e.nsDecls.get(prefix);
    return prefix === '' ? '' : null;
  }
  textContent() {
    let s = '';
    for (const c of this.children) {
      if (c.type === 'text') s += c.value;
      else if (c.type === 'element') s += c.textContent();
    }
    return s;
  }
}

export class Text extends Node {
  constructor(value, cdata = false) {
    super('text');
    this.value = value;
    this.cdata = cdata;
  }
}

export class Comment extends Node {
  constructor(value) {
    super('comment');
    this.value = value;
  }
}

export class PI extends Node {
  constructor(target, value) {
    super('pi');
    this.target = target;
    this.value = value;
  }
}

export class Document extends Node {
  constructor() {
    super('document');
    this.children = [];
    this.xmlStandalone = false; // standalone="yes" in the XML declaration (Document.getXmlStandalone())
  }
  get documentElement() {
    return this.children.find((c) => c.type === 'element') || null;
  }
  appendChild(node) {
    node.parent = this;
    this.children.push(node);
    return node;
  }
}

function decodeEntities(s, pos, inAttr) {
  // resolves &...; references
  let out = '';
  let i = 0;
  for (;;) {
    const j = s.indexOf('&', i);
    if (j < 0) {
      out += s.slice(i);
      break;
    }
    out += s.slice(i, j);
    const k = s.indexOf(';', j);
    if (k < 0) throw new XmlError(`XML: unterminated entity reference near position ${pos + j}`);
    const ent = s.slice(j + 1, k);
    if (ent[0] === '#') {
      const cp = ent[1] === 'x' ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10);
      if (!Number.isFinite(cp) || cp <= 0 || cp > 0x10ffff) throw new XmlError('XML: bad character reference &' + ent + ';');
      out += String.fromCodePoint(cp);
    } else if (PREDEF[ent] !== undefined) {
      out += PREDEF[ent];
    } else {
      throw new XmlError(`XML: undefined entity &${ent};`);
    }
    i = k + 1;
  }
  return out;
}

/** Parse an XML string. */
export function parseXml(input) {
  if (typeof input !== 'string') throw new XmlError('XML input must be a string');
  // strip BOM, normalize line endings (XML 1.0 §2.11)
  let s = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
  s = s.replace(/\r\n?/g, '\n');
  const doc = new Document();
  let pos = 0;
  const n = s.length;
  let cur = doc;
  let sawRoot = false;
  const fail = (msg) => {
    throw new XmlError(`XML: ${msg} (позиция ${pos})`);
  };

  const readName = () => {
    const start = pos;
    while (pos < n) {
      const c = s.charCodeAt(pos);
      if (isWs(c) || c === 0x2f || c === 0x3e || c === 0x3d || c === 0x3f || c === 0x22 || c === 0x27 || c === 0x3c) break;
      pos++;
    }
    if (pos === start) fail('ожидалось имя');
    return s.slice(start, pos);
  };
  const skipWs = () => {
    while (pos < n && isWs(s.charCodeAt(pos))) pos++;
  };

  // XML declaration
  if (s.startsWith('<?xml') && isWs(s.charCodeAt(5))) {
    const e = s.indexOf('?>');
    if (e < 0) fail('незавершённое объявление XML');
    doc.xmlStandalone = /\sstandalone\s*=\s*(["'])yes\1/.test(s.slice(5, e));
    pos = e + 2;
  }

  const pendingText = [];
  const flushText = () => {
    if (!pendingText.length) return;
    const text = pendingText.join('');
    pendingText.length = 0;
    if (cur === doc) {
      if (/[^ \t\n]/.test(text)) fail('текст вне корневого элемента');
      return;
    }
    const last = cur.children[cur.children.length - 1];
    if (last && last.type === 'text' && !last.cdata) last.value += text;
    else cur.appendChild(new Text(text));
  };

  while (pos < n) {
    const lt = s.indexOf('<', pos);
    if (lt < 0) {
      pendingText.push(decodeEntities(s.slice(pos), pos));
      pos = n;
      break;
    }
    if (lt > pos) {
      const raw = s.slice(pos, lt);
      if (raw.includes(']]>')) fail("последовательность ']]>' в тексте");
      pendingText.push(decodeEntities(raw, pos));
      pos = lt;
    }
    if (s.startsWith('<!--', pos)) {
      flushText();
      const e = s.indexOf('-->', pos + 4);
      if (e < 0) fail('незавершённый комментарий');
      const c = new Comment(s.slice(pos + 4, e));
      if (cur === doc) doc.appendChild(c);
      else cur.appendChild(c);
      pos = e + 3;
    } else if (s.startsWith('<![CDATA[', pos)) {
      if (cur === doc) fail('CDATA вне корневого элемента');
      flushText();
      const e = s.indexOf(']]>', pos + 9);
      if (e < 0) fail('незавершённая секция CDATA');
      cur.appendChild(new Text(s.slice(pos + 9, e), true));
      pos = e + 3;
    } else if (s.startsWith('<!DOCTYPE', pos) || s.startsWith('<!doctype', pos)) {
      fail('DOCTYPE запрещён');
    } else if (s.startsWith('<?', pos)) {
      flushText();
      pos += 2;
      const target = readName();
      if (target.toLowerCase() === 'xml') fail('объявление XML не в начале документа');
      const e = s.indexOf('?>', pos);
      if (e < 0) fail('незавершённая инструкция обработки');
      let data = s.slice(pos, e);
      data = data.replace(/^[ \t\n]+/, '');
      const pi = new PI(target, data);
      if (cur === doc) doc.appendChild(pi);
      else cur.appendChild(pi);
      pos = e + 2;
    } else if (s.startsWith('</', pos)) {
      flushText();
      pos += 2;
      const name = readName();
      skipWs();
      if (s[pos] !== '>') fail('ожидался >');
      pos++;
      if (cur === doc || cur.name !== name) fail(`несовпадающий закрывающий тег </${name}>`);
      cur = cur.parent;
    } else {
      // start tag
      flushText();
      pos++;
      const name = readName();
      if (cur === doc) {
        if (sawRoot) fail('более одного корневого элемента');
        sawRoot = true;
      }
      const el = new Element(name);
      const seen = new Set();
      for (;;) {
        const before = pos;
        skipWs();
        const c = s[pos];
        if (c === '>' || c === '/') break;
        if (pos === before) fail('ожидался пробел между атрибутами');
        const an = readName();
        skipWs();
        if (s[pos] !== '=') fail('ожидался = после имени атрибута');
        pos++;
        skipWs();
        const q = s[pos];
        if (q !== '"' && q !== "'") fail('ожидалась кавычка');
        const e = s.indexOf(q, pos + 1);
        if (e < 0) fail('незавершённое значение атрибута');
        const rawVal = s.slice(pos + 1, e);
        if (rawVal.includes('<')) fail('символ < в значении атрибута');
        // attribute value normalization: literal whitespace -> space, then resolve refs
        const val = decodeEntities(rawVal.replace(/[\t\n]/g, ' '), pos, true);
        pos = e + 1;
        if (seen.has(an)) fail('повторяющийся атрибут ' + an);
        seen.add(an);
        const i = an.indexOf(':');
        const attr = { name: an, prefix: i >= 0 ? an.slice(0, i) : '', localName: i >= 0 ? an.slice(i + 1) : an, ns: '', value: val };
        if (an === 'xmlns') {
          el.nsDecls.set('', val);
          attr.ns = XMLNS_NS;
          attr.isNsDecl = true;
        } else if (attr.prefix === 'xmlns') {
          if (val === '') fail('пустое пространство имён для префикса ' + attr.localName);
          el.nsDecls.set(attr.localName, val);
          attr.ns = XMLNS_NS;
          attr.isNsDecl = true;
        }
        el.attrs.push(attr);
      }
      if (cur === doc) doc.appendChild(el);
      else cur.appendChild(el);
      // resolve namespaces
      const ens = el.lookupNamespace(el.prefix);
      if (ens === null) fail('неизвестный префикс ' + el.prefix);
      el.ns = ens;
      const expanded = new Set();
      for (const a of el.attrs) {
        if (a.isNsDecl) continue;
        if (a.prefix) {
          const u = el.lookupNamespace(a.prefix);
          if (u === null) fail('неизвестный префикс атрибута ' + a.prefix);
          a.ns = u;
        }
        const key = a.ns + '|' + a.localName;
        if (expanded.has(key)) fail('повторяющийся атрибут ' + a.name);
        expanded.add(key);
      }
      if (s[pos] === '/') {
        if (s[pos + 1] !== '>') fail('ожидался />');
        pos += 2;
      } else {
        pos++;
        cur = el;
      }
    }
  }
  flushText();
  if (cur !== doc) fail(`не закрыт элемент <${cur.name}>`);
  if (!doc.documentElement) throw new XmlError('XML: нет корневого элемента');
  return doc;
}

// ---------------------------------------------------------------- serializer (Xalan-like)

const ENTITY = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
const charRef = (c) => ENTITY[c] || '&#' + c.codePointAt(0) + ';';

// Xalan ToStream: in text CR, DEL/C1 controls and supplementary characters become character references;
// in attribute values TAB/LF/CR and supplementary characters do.
function escText(s) {
  return s.replace(/[&<>\r\x7f-\x9f]|[\ud800-\udbff][\udc00-\udfff]/g, charRef);
}

function escAttr(s) {
  return s.replace(/[&<>"\n\r\t]|[\ud800-\udbff][\udc00-\udfff]/g, charRef);
}

function compareJava(a, b) {
  // String.compareTo: UTF-16 code unit order
  return a < b ? -1 : a > b ? 1 : 0;
}

const isNsDeclName = (name) => name === 'xmlns' || name.startsWith('xmlns:');

/**
 * Serialize like javax.xml.transform (JDK Xalan DOM2TO + ToStream) with OMIT_XML_DECLARATION=yes: attributes come
 * in Xerces DOM order (sorted by qualified name) with namespace declarations first, declarations that repeat a
 * mapping already in scope are dropped (NamespaceMappings), empty elements are written as <a/>, CR as &#13;.
 */
export function serialize(node) {
  let out = '';
  const walk = (nd, scope) => {
    switch (nd.type) {
      case 'document':
        for (const c of nd.children) walk(c, scope);
        break;
      case 'element': {
        out += '<' + nd.name;
        const attrs = [...nd.attrs].sort((a, b) => compareJava(a.name, b.name));
        let inner = scope;
        for (const a of attrs) {
          if (!isNsDeclName(a.name)) continue;
          const prefix = a.name === 'xmlns' ? '' : a.name.slice(6);
          if (prefix.startsWith('xml') || scope.get(prefix) === a.value) continue;
          if (inner === scope) inner = new Map(scope);
          inner.set(prefix, a.value);
          out += ' ' + a.name + '="' + escAttr(a.value) + '"';
        }
        for (const a of attrs) if (!isNsDeclName(a.name)) out += ' ' + a.name + '="' + escAttr(a.value) + '"';
        if (!nd.children.length) {
          out += '/>';
        } else {
          out += '>';
          for (const c of nd.children) walk(c, inner);
          out += '</' + nd.name + '>';
        }
        break;
      }
      case 'text':
        if (nd.cdata) out += '<![CDATA[' + nd.value.split(']]>').join(']]]]><![CDATA[>') + ']]>';
        else out += escText(nd.value);
        break;
      case 'comment':
        out += '<!--' + nd.value + '-->';
        break;
      case 'pi':
        out += '<?' + nd.target + (nd.value ? ' ' + nd.value : '') + '?>';
        break;
      default:
        break;
    }
  };
  walk(node, new Map([['', ''], ['xml', XML_NS]]));
  return out;
}

/** XML declaration a default JDK 8 Transformer writes for a DOMSource(Document); no line break follows it. */
export function xmlDeclaration(doc) {
  return doc.xmlStandalone ? '<?xml version="1.0" encoding="UTF-8"?>' : '<?xml version="1.0" encoding="UTF-8" standalone="no"?>';
}

/** Create an element in a namespace with the given qualified name (declaration is added by the caller). */
export function createElement(qname, ns) {
  const el = new Element(qname);
  el.ns = ns || '';
  return el;
}

/** Path of child indices from the document to `node` (used to map browser DOM results onto this tree). */
export function nodePath(node) {
  const path = [];
  for (let n = node; n.parent; n = n.parent) path.unshift(n.parent.children.indexOf(n));
  return path;
}

export function nodeAtPath(doc, path) {
  let n = doc;
  for (const i of path) {
    n = n.children[i];
    if (!n) return null;
  }
  return n;
}
