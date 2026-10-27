// Small XPath 1.0 subset evaluator for the tree from dom.js (element selection for tbsElementXPath /
// signatureParentElementXPath). In the browser the full XPath engine (document.evaluate) is preferred
// via evaluateXPathElement(); this implementation is the fallback (and is used in Node tests).
import { parseXml, nodePath, nodeAtPath } from './dom.js';

const SOAP_NS = 'http://schemas.xmlsoap.org/soap/envelope/';
const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';

/** Kalkan XMLUtil.PkiNamespaceContext: SOAP-ENV -> SOAP 1.1 envelope, any other prefix -> xmldsig. */
export function kalkanNsResolver(prefix) {
  return prefix === 'SOAP-ENV' ? SOAP_NS : DS_NS;
}

// ------------------------------------------------------------ tokenizer

function tokenize(expr) {
  const toks = [];
  let i = 0;
  while (i < expr.length) {
    const c = expr[i];
    if (/\s/.test(c)) { i++; continue; }
    if (expr.startsWith('//', i)) { toks.push({ t: '//' }); i += 2; continue; }
    if (expr.startsWith('..', i)) { toks.push({ t: '..' }); i += 2; continue; }
    if (expr.startsWith('::', i)) { toks.push({ t: '::' }); i += 2; continue; }
    if (expr.startsWith('!=', i) || expr.startsWith('<=', i) || expr.startsWith('>=', i)) { toks.push({ t: expr.substr(i, 2) }); i += 2; continue; }
    if ('/[]()@,=|<>*.+-'.includes(c)) {
      if (c === '.' && /[0-9]/.test(expr[i + 1] || '')) {
        const m = /^\.[0-9]+/.exec(expr.slice(i));
        toks.push({ t: 'num', v: parseFloat(m[0]) });
        i += m[0].length;
        continue;
      }
      toks.push({ t: c });
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      const e = expr.indexOf(c, i + 1);
      if (e < 0) throw new Error('XPath: unterminated string');
      toks.push({ t: 'str', v: expr.slice(i + 1, e) });
      i = e + 1;
      continue;
    }
    if (/[0-9]/.test(c)) {
      const m = /^[0-9]+(\.[0-9]+)?/.exec(expr.slice(i));
      toks.push({ t: 'num', v: parseFloat(m[0]) });
      i += m[0].length;
      continue;
    }
    const m = /^[A-Za-z_\u00C0-\uFFFF][\w.\-\u00B7\u00C0-\uFFFF]*(:[A-Za-z_\u00C0-\uFFFF*][\w.\-\u00B7\u00C0-\uFFFF]*)?/.exec(expr.slice(i));
    if (!m) throw new Error('XPath: unexpected character ' + c);
    // name:* handled by regex allowing '*' after colon
    toks.push({ t: 'name', v: m[0] });
    i += m[0].length;
  }
  return toks;
}

// ------------------------------------------------------------ parser -> AST

class Parser {
  constructor(toks) {
    this.toks = toks;
    this.i = 0;
  }
  peek(k = 0) {
    return this.toks[this.i + k];
  }
  next() {
    return this.toks[this.i++];
  }
  accept(t) {
    if (this.peek() && this.peek().t === t) return this.next();
    return null;
  }
  expect(t) {
    const x = this.next();
    if (!x || x.t !== t) throw new Error('XPath: expected ' + t);
    return x;
  }
  parseExpr() {
    return this.parseOr();
  }
  parseOr() {
    let l = this.parseAnd();
    while (this.peek() && this.peek().t === 'name' && this.peek().v === 'or') {
      this.next();
      l = { op: 'or', l, r: this.parseAnd() };
    }
    return l;
  }
  parseAnd() {
    let l = this.parseEq();
    while (this.peek() && this.peek().t === 'name' && this.peek().v === 'and') {
      this.next();
      l = { op: 'and', l, r: this.parseEq() };
    }
    return l;
  }
  parseEq() {
    let l = this.parseRel();
    while (this.peek() && (this.peek().t === '=' || this.peek().t === '!=')) {
      const op = this.next().t;
      l = { op, l, r: this.parseRel() };
    }
    return l;
  }
  parseRel() {
    let l = this.parseAdd();
    while (this.peek() && ['<', '>', '<=', '>='].includes(this.peek().t)) {
      const op = this.next().t;
      l = { op, l, r: this.parseAdd() };
    }
    return l;
  }
  parseAdd() {
    let l = this.parseUnion();
    while (this.peek() && (this.peek().t === '+' || this.peek().t === '-')) {
      const op = this.next().t;
      l = { op, l, r: this.parseUnion() };
    }
    return l;
  }
  parseUnion() {
    let l = this.parsePath();
    while (this.accept('|')) l = { op: '|', l, r: this.parsePath() };
    return l;
  }
  parsePath() {
    const p = this.peek();
    if (!p) throw new Error('XPath: unexpected end');
    if (p.t === 'str') { this.next(); return { lit: p.v }; }
    if (p.t === 'num') { this.next(); return { lit: p.v }; }
    if (p.t === '(') {
      this.next();
      const e = this.parseExpr();
      this.expect(')');
      return e;
    }
    if (p.t === 'name' && this.peek(1) && this.peek(1).t === '(' && !['node', 'text', 'comment'].includes(p.v)) {
      this.next();
      this.next();
      const args = [];
      if (!this.accept(')')) {
        do args.push(this.parseExpr());
        while (this.accept(','));
        this.expect(')');
      }
      return { fn: p.v, args };
    }
    return this.parseLocationPath();
  }
  parseLocationPath() {
    const steps = [];
    let absolute = false;
    if (this.accept('/')) {
      absolute = true;
      if (!this.peek() || !['name', '*', '@', '.', '..'].includes(this.peek().t)) return { path: { absolute, steps } };
    } else if (this.accept('//')) {
      absolute = true;
      steps.push({ axis: 'descendant-or-self', test: { type: 'node' }, preds: [] });
    }
    steps.push(this.parseStep());
    for (;;) {
      if (this.accept('/')) steps.push(this.parseStep());
      else if (this.accept('//')) {
        steps.push({ axis: 'descendant-or-self', test: { type: 'node' }, preds: [] });
        steps.push(this.parseStep());
      } else break;
    }
    return { path: { absolute, steps } };
  }
  parseStep() {
    if (this.accept('.')) return { axis: 'self', test: { type: 'node' }, preds: [] };
    if (this.accept('..')) return { axis: 'parent', test: { type: 'node' }, preds: [] };
    let axis = 'child';
    if (this.accept('@')) axis = 'attribute';
    else if (this.peek() && this.peek().t === 'name' && this.peek(1) && this.peek(1).t === '::') {
      axis = this.next().v;
      this.next();
    }
    let test;
    if (this.accept('*')) test = { type: 'name', prefix: null, local: '*' };
    else {
      const n = this.expect('name').v;
      if (this.peek() && this.peek().t === '(' && ['node', 'text', 'comment'].includes(n)) {
        this.next();
        this.expect(')');
        test = { type: n };
      } else {
        const i = n.indexOf(':');
        test = { type: 'name', prefix: i >= 0 ? n.slice(0, i) : null, local: i >= 0 ? n.slice(i + 1) : n };
      }
    }
    const preds = [];
    while (this.accept('[')) {
      preds.push(this.parseExpr());
      this.expect(']');
    }
    return { axis, test, preds };
  }
}

// ------------------------------------------------------------ evaluation

function stringValue(n) {
  if (n.kind === 'attr') return n.attr.value;
  if (n.type === 'text' || n.type === 'comment') return n.value;
  if (n.type === 'element') return n.textContent();
  if (n.type === 'document') return n.documentElement ? n.documentElement.textContent() : '';
  return '';
}

function toStr(v) {
  if (Array.isArray(v)) return v.length ? stringValue(v[0]) : '';
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : String(v);
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  return v;
}

function toNum(v) {
  return Number(toStr(v).trim() || NaN);
}

function toBool(v) {
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === 'number') return v !== 0 && !Number.isNaN(v);
  if (typeof v === 'string') return v.length > 0;
  return !!v;
}

function compare(op, a, b) {
  const cmpVals = (x, y) => {
    if (op === '=' || op === '!=') {
      let r;
      if (typeof x === 'boolean' || typeof y === 'boolean') r = toBool(x) === toBool(y);
      else if (typeof x === 'number' || typeof y === 'number') r = toNum(x) === toNum(y);
      else r = toStr(x) === toStr(y);
      return op === '=' ? r : !r;
    }
    const nx = toNum(x), ny = toNum(y);
    return op === '<' ? nx < ny : op === '>' ? nx > ny : op === '<=' ? nx <= ny : nx >= ny;
  };
  if (Array.isArray(a) || Array.isArray(b)) {
    const as = Array.isArray(a) ? a.map(stringValue) : [a];
    const bs = Array.isArray(b) ? b.map(stringValue) : [b];
    for (const x of as) for (const y of bs) if (cmpVals(x, y)) return true;
    return false;
  }
  return cmpVals(a, b);
}

function matchesTest(n, test, axis, nsResolver) {
  if (test.type === 'node') return true;
  if (test.type === 'text') return n.type === 'text';
  if (test.type === 'comment') return n.type === 'comment';
  if (axis === 'attribute') {
    const a = n.attr;
    if (test.local !== '*' && a.localName !== test.local) return false;
    if (test.prefix === null) return test.local === '*' || a.ns === '';
    return a.ns === nsResolver(test.prefix);
  }
  if (n.type !== 'element') return false;
  if (test.local !== '*' && n.localName !== test.local) return false;
  if (test.prefix === null) return test.local === '*' || n.ns === '';
  return n.ns === nsResolver(test.prefix);
}

function axisNodes(ctx, axis) {
  const out = [];
  const kids = (n) => (n.children || []);
  switch (axis) {
    case 'child':
      return kids(ctx).slice();
    case 'self':
      return [ctx];
    case 'parent':
      return ctx.parent ? [ctx.parent] : [];
    case 'attribute':
      return ctx.type === 'element' ? ctx.attrs.filter((a) => !a.isNsDecl).map((attr) => ({ kind: 'attr', attr, parent: ctx })) : [];
    case 'descendant':
    case 'descendant-or-self': {
      if (axis === 'descendant-or-self') out.push(ctx);
      const walk = (n) => {
        for (const c of kids(n)) {
          out.push(c);
          walk(c);
        }
      };
      walk(ctx);
      return out;
    }
    case 'ancestor':
    case 'ancestor-or-self': {
      if (axis === 'ancestor-or-self') out.push(ctx);
      for (let p = ctx.parent; p; p = p.parent) out.push(p);
      return out;
    }
    case 'following-sibling':
    case 'preceding-sibling': {
      if (!ctx.parent) return [];
      const sib = ctx.parent.children;
      const i = sib.indexOf(ctx);
      return axis === 'following-sibling' ? sib.slice(i + 1) : sib.slice(0, i).reverse();
    }
    default:
      throw new Error('XPath: unsupported axis ' + axis);
  }
}

function evalExpr(e, ctx, pos, size, nsResolver, doc) {
  if (e.lit !== undefined) return e.lit;
  if (e.path) return evalPath(e.path, ctx, nsResolver, doc);
  if (e.fn) {
    const a = (i) => evalExpr(e.args[i], ctx, pos, size, nsResolver, doc);
    switch (e.fn) {
      case 'position': return pos;
      case 'last': return size;
      case 'count': return a(0).length;
      case 'not': return !toBool(a(0));
      case 'true': return true;
      case 'false': return false;
      case 'string': return e.args.length ? toStr(a(0)) : stringValue(ctx);
      case 'number': return e.args.length ? toNum(a(0)) : toNum(stringValue(ctx));
      case 'concat': return e.args.map((_, i) => toStr(a(i))).join('');
      case 'contains': return toStr(a(0)).includes(toStr(a(1)));
      case 'starts-with': return toStr(a(0)).startsWith(toStr(a(1)));
      case 'normalize-space': return (e.args.length ? toStr(a(0)) : stringValue(ctx)).trim().replace(/\s+/g, ' ');
      case 'string-length': return (e.args.length ? toStr(a(0)) : stringValue(ctx)).length;
      case 'local-name': {
        const n = e.args.length ? a(0)[0] : ctx;
        return !n ? '' : n.kind === 'attr' ? n.attr.localName : n.localName || '';
      }
      case 'name': {
        const n = e.args.length ? a(0)[0] : ctx;
        return !n ? '' : n.kind === 'attr' ? n.attr.name : n.name || '';
      }
      case 'namespace-uri': {
        const n = e.args.length ? a(0)[0] : ctx;
        return !n ? '' : n.kind === 'attr' ? n.attr.ns : n.ns || '';
      }
      default:
        throw new Error('XPath: unsupported function ' + e.fn + '()');
    }
  }
  const l = evalExpr(e.l, ctx, pos, size, nsResolver, doc);
  if (e.op === 'and') return toBool(l) && toBool(evalExpr(e.r, ctx, pos, size, nsResolver, doc));
  if (e.op === 'or') return toBool(l) || toBool(evalExpr(e.r, ctx, pos, size, nsResolver, doc));
  const r = evalExpr(e.r, ctx, pos, size, nsResolver, doc);
  if (e.op === '|') return [...new Set([...l, ...r])];
  if (e.op === '+') return toNum(l) + toNum(r);
  if (e.op === '-') return toNum(l) - toNum(r);
  return compare(e.op, l, r);
}

function evalPath(path, ctx, nsResolver, doc) {
  let nodes = [path.absolute ? doc : ctx];
  for (const step of path.steps) {
    const next = [];
    for (const n of nodes) {
      let cand = axisNodes(n, step.axis).filter((c) => matchesTest(c, step.test, step.axis, nsResolver));
      for (const pred of step.preds) {
        const size = cand.length;
        cand = cand.filter((c, i) => {
          const v = evalExpr(pred, c, i + 1, size, nsResolver, doc);
          return typeof v === 'number' ? v === i + 1 : toBool(v);
        });
      }
      for (const c of cand) if (!next.includes(c)) next.push(c);
    }
    nodes = next;
  }
  return nodes;
}

/** Evaluate an XPath expression on our tree and return the first element node (or null). */
export function selectElement(doc, expr, nsResolver = kalkanNsResolver) {
  const p = new Parser(tokenize(expr));
  const ast = p.parseExpr();
  if (p.peek()) throw new Error('XPath: unexpected token');
  const res = evalExpr(ast, doc, 1, 1, nsResolver, doc);
  if (!Array.isArray(res)) return null;
  // document order
  const first = res.find((n) => n.type === 'element');
  return first || null;
}

/**
 * Evaluate with the browser XPath engine when available (full XPath 1.0), mapping the result back onto our tree.
 * Falls back to the built-in evaluator.
 */
export function evaluateXPathElement(doc, xmlString, expr) {
  const g = globalThis;
  if (g.DOMParser && g.XPathResult) {
    try {
      const bdoc = new g.DOMParser().parseFromString(xmlString, 'application/xml');
      if (!bdoc.getElementsByTagName('parsererror').length) {
        const r = bdoc.evaluate(expr, bdoc, kalkanNsResolver, g.XPathResult.FIRST_ORDERED_NODE_TYPE, null);
        const bn = r.singleNodeValue;
        if (!bn) return null;
        if (bn.nodeType !== 1) return null;
        // path of element-only indices is not stable across parsers (text node merging); map by element index path
        const idx = [];
        for (let n = bn; n.parentNode && n.parentNode.nodeType !== 9; n = n.parentNode) {
          let i = 0;
          for (let s = n.previousElementSibling; s; s = s.previousElementSibling) i++;
          idx.unshift(i);
        }
        let cur = doc.documentElement;
        for (const i of idx) {
          cur = cur.children.filter((c) => c.type === 'element')[i];
          if (!cur) return null;
        }
        return cur;
      }
    } catch {
      /* fall back */
    }
  }
  return selectElement(doc, expr);
}

export { parseXml, nodePath, nodeAtPath };
