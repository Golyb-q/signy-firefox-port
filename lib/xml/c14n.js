// Canonical XML 1.0 (inclusive) and Exclusive XML Canonicalization 1.0 over the tree from dom.js.
// Only the node-sets needed for XMLDSig are supported: a whole document or an element subtree, optionally
// excluding some element subtrees (enveloped-signature transform) and comments.
import { XML_NS } from './dom.js';

function escText(s) {
  return s.replace(/[&<>\r]/g, (c) => (c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : '&#xD;'));
}

function escAttr(s) {
  return s.replace(/[&<"\t\n\r]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '"': '&quot;', '\t': '&#x9;', '\n': '&#xA;', '\r': '&#xD;' })[c]);
}

function cmp(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * @param {object} opts
 *   exclusive: boolean
 *   withComments: boolean
 *   exclude: (node) => boolean  - nodes (and their subtrees) removed from the node-set
 *   inclusivePrefixes: string[] (exclusive only)
 */
export function canonicalize(node, opts = {}) {
  const { exclusive = false, withComments = false, exclude = () => false, inclusivePrefixes = [] } = opts;
  const out = [];

  // rendered: Map prefix -> uri of namespace declarations rendered by the nearest output ancestor (cumulative)
  const renderElement = (el, rendered, isApex) => {
    const inScope = el.inScopeNamespaces();
    const nsOut = []; // [prefix, uri]
    const nextRendered = new Map(rendered);
    if (!exclusive) {
      for (const [p, u] of inScope) {
        if (p === 'xml') continue;
        if (p === '') {
          const parentDefault = rendered.get('') || '';
          if (u !== parentDefault) nsOut.push(['', u]);
          continue;
        }
        if (rendered.get(p) !== u) nsOut.push([p, u]);
      }
      // default namespace undeclared in scope but rendered non-empty by ancestor => xmlns=""
      if (!inScope.has('') && (rendered.get('') || '') !== '') nsOut.push(['', '']);
    } else {
      const utilized = new Set();
      utilized.add(el.prefix); // '' = default
      for (const a of el.attrs) if (!a.isNsDecl && a.prefix && a.prefix !== 'xml') utilized.add(a.prefix);
      for (const p of inclusivePrefixes) utilized.add(p === '#default' ? '' : p);
      for (const p of utilized) {
        if (p === 'xml') continue;
        const u = p === '' ? inScope.get('') || '' : inScope.get(p);
        if (u === undefined) continue;
        const prev = rendered.has(p) ? rendered.get(p) : p === '' ? '' : undefined;
        if (prev !== u) {
          if (p === '' && u === '' && !rendered.has('')) continue;
          nsOut.push([p, u]);
        }
      }
    }
    for (const [p, u] of nsOut) nextRendered.set(p, u);
    nsOut.sort((a, b) => cmp(a[0], b[0])); // default ('') first, then by prefix

    // attributes (excluding namespace declarations)
    let attrs = el.attrs.filter((a) => !a.isNsDecl);
    if (!exclusive && isApex) {
      // C14N 1.0: inherit xml:* attributes from ancestors outside the node-set
      const have = new Set(attrs.filter((a) => a.ns === XML_NS).map((a) => a.localName));
      for (let anc = el.parent; anc && anc.type === 'element'; anc = anc.parent) {
        for (const a of anc.attrs) {
          if (a.ns === XML_NS && !have.has(a.localName)) {
            have.add(a.localName);
            attrs = attrs.concat([a]);
          }
        }
      }
    }
    attrs = attrs.slice().sort((a, b) => cmp(a.ns, b.ns) || cmp(a.localName, b.localName));

    out.push('<', el.name);
    for (const [p, u] of nsOut) out.push(' ', p ? 'xmlns:' + p : 'xmlns', '="', escAttr(u), '"');
    for (const a of attrs) out.push(' ', a.name, '="', escAttr(a.value), '"');
    out.push('>');
    for (const c of el.children) renderNode(c, nextRendered, false);
    out.push('</', el.name, '>');
  };

  const renderNode = (n, rendered, isApex) => {
    if (exclude(n)) return;
    switch (n.type) {
      case 'element':
        renderElement(n, rendered, isApex);
        break;
      case 'text':
        out.push(escText(n.value));
        break;
      case 'comment':
        if (withComments) out.push('<!--', n.value, '-->');
        break;
      case 'pi':
        out.push('<?', n.target, n.value ? ' ' + n.value : '', '?>');
        break;
      default:
        break;
    }
  };

  if (node.type === 'document') {
    const root = node.documentElement;
    let seenRoot = false;
    for (const c of node.children) {
      if (exclude(c)) continue;
      if (c === root) {
        renderNode(c, new Map(), true);
        seenRoot = true;
        continue;
      }
      if (c.type === 'comment' && !withComments) continue;
      if (c.type !== 'comment' && c.type !== 'pi') continue;
      if (seenRoot) out.push('\n');
      renderNode(c, new Map(), false);
      if (!seenRoot) out.push('\n');
    }
  } else {
    renderNode(node, new Map(), true);
  }
  return out.join('');
}
