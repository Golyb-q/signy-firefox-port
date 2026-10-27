// Minimal ASN.1 BER/DER decoder and DER encoder.
import { concat, bytesToBigInt, bigIntToJavaBytes, utf8Encode, utf8Decode, toHex } from './util.js';

export const TAG = {
  BOOLEAN: 1, INTEGER: 2, BIT_STRING: 3, OCTET_STRING: 4, NULL: 5, OID: 6, UTF8: 12,
  SEQUENCE: 16, SET: 17, NUMERIC: 18, PRINTABLE: 19, T61: 20, IA5: 22, UTC_TIME: 23,
  GENERALIZED_TIME: 24, VISIBLE: 26, UNIVERSAL: 28, BMP: 30,
};

export class Asn1Error extends Error {}

export class Node {
  constructor(buf, start, headerLen, len, cls, constructed, tagNum, indefinite) {
    this.buf = buf;
    this.start = start; // offset of the tag byte
    this.headerLen = headerLen;
    this.len = len; // content length (for indefinite: computed, without EOC)
    this.cls = cls; // 0 universal, 1 application, 2 context, 3 private
    this.constructed = constructed;
    this.tagNum = tagNum;
    this.indefinite = indefinite;
    this.children = null;
    this.totalLen = headerLen + len + (indefinite ? 2 : 0);
  }
  get end() {
    return this.start + this.totalLen;
  }
  /** Full TLV bytes as they appear in the input. */
  get bytes() {
    return this.buf.subarray(this.start, this.end);
  }
  /** Content octets (for primitive nodes). */
  get content() {
    return this.buf.subarray(this.start + this.headerLen, this.start + this.headerLen + this.len);
  }
  is(cls, tagNum) {
    return this.cls === cls && this.tagNum === tagNum;
  }
  isUniversal(tagNum) {
    return this.cls === 0 && this.tagNum === tagNum;
  }
  isContext(n) {
    return this.cls === 2 && this.tagNum === n;
  }
  child(i) {
    if (!this.children || i >= this.children.length) throw new Asn1Error(`ASN.1: missing element #${i}`);
    return this.children[i];
  }
  get count() {
    return this.children ? this.children.length : 0;
  }
  expect(tagNum, what = '') {
    if (!this.isUniversal(tagNum)) throw new Asn1Error(`ASN.1: expected universal tag ${tagNum} ${what}, got cls=${this.cls} tag=${this.tagNum}`);
    return this;
  }
  toBigInt() {
    this.expect(TAG.INTEGER, 'INTEGER');
    const c = this.content;
    let v = bytesToBigInt(c);
    if (c.length && c[0] & 0x80) v -= 1n << BigInt(c.length * 8);
    return v;
  }
  toNumber() {
    return Number(this.toBigInt());
  }
  toOid() {
    this.expect(TAG.OID, 'OID');
    return decodeOid(this.content);
  }
  toBool() {
    this.expect(TAG.BOOLEAN, 'BOOLEAN');
    return this.content[0] !== 0;
  }
  /** Bit string content without the unused-bits octet. */
  toBitString() {
    this.expect(TAG.BIT_STRING, 'BIT STRING');
    if (this.constructed) throw new Asn1Error('constructed BIT STRING not supported');
    const c = this.content;
    return { unused: c[0], bytes: c.subarray(1) };
  }
  /** Octet string content (handles BER constructed octet strings). */
  toOctets() {
    if (!this.constructed) return this.content;
    return concat(...this.children.map((c) => c.toOctets()));
  }
  toStr() {
    const c = this.cls === 0 ? this.tagNum : -1;
    const b = this.constructed ? this.toOctets() : this.content;
    switch (c) {
      case TAG.BMP: {
        let s = '';
        for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] << 8) | b[i + 1]);
        return s;
      }
      case TAG.UNIVERSAL: {
        let s = '';
        for (let i = 0; i + 3 < b.length; i += 4) s += String.fromCodePoint(((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0);
        return s;
      }
      case TAG.T61: {
        // Most T61/Teletex strings in practice are Latin-1 (or UTF-8 misuse). Try UTF-8 first.
        try {
          return new TextDecoder('utf-8', { fatal: true }).decode(b);
        } catch {
          return String.fromCharCode(...b);
        }
      }
      case TAG.PRINTABLE:
      case TAG.IA5:
      case TAG.VISIBLE:
      case TAG.NUMERIC:
        return String.fromCharCode(...b);
      default:
        return utf8Decode(b);
    }
  }
  toDate() {
    const s = String.fromCharCode(...this.content);
    if (this.isUniversal(TAG.UTC_TIME)) return parseUtcTime(s);
    if (this.isUniversal(TAG.GENERALIZED_TIME)) return parseGeneralizedTime(s);
    throw new Asn1Error('ASN.1: not a time value');
  }
}

function parseUtcTime(s) {
  const m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?(Z|[+-]\d{4})?$/.exec(s);
  if (!m) throw new Asn1Error('bad UTCTime ' + s);
  let y = +m[1];
  y += y < 50 ? 2000 : 1900;
  return makeDate(y, m[2], m[3], m[4], m[5], m[6] || '0', '', m[7] || 'Z');
}

function parseGeneralizedTime(s) {
  const m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)?(\d\d)?(?:[.,](\d+))?(Z|[+-]\d{4})?$/.exec(s);
  if (!m) throw new Asn1Error('bad GeneralizedTime ' + s);
  return makeDate(+m[1], m[2], m[3], m[4], m[5] || '0', m[6] || '0', m[7] || '', m[8] || 'Z');
}

function makeDate(y, mo, d, h, mi, se, frac, tz) {
  let t = Date.UTC(y, +mo - 1, +d, +h, +mi, +se, frac ? Math.round(+('0.' + frac) * 1000) : 0);
  if (tz && tz !== 'Z') {
    const sign = tz[0] === '-' ? -1 : 1;
    t -= sign * (+tz.substr(1, 2) * 60 + +tz.substr(3, 2)) * 60000;
  }
  return new Date(t);
}

export function decodeOid(bytes) {
  const parts = [];
  let v = 0n;
  for (let i = 0; i < bytes.length; i++) {
    v = (v << 7n) | BigInt(bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) {
      if (parts.length === 0) {
        const first = v < 80n ? v / 40n : 2n;
        parts.push(first, v - first * 40n);
      } else parts.push(v);
      v = 0n;
    }
  }
  return parts.join('.');
}

function parseNode(buf, pos, limit, depth) {
  if (depth > 64) throw new Asn1Error('ASN.1: nesting too deep');
  if (pos + 2 > limit) throw new Asn1Error('ASN.1: truncated header');
  const start = pos;
  const b0 = buf[pos++];
  const cls = b0 >> 6;
  const constructed = !!(b0 & 0x20);
  let tagNum = b0 & 0x1f;
  if (tagNum === 0x1f) {
    tagNum = 0;
    let b;
    do {
      if (pos >= limit) throw new Asn1Error('ASN.1: truncated tag');
      b = buf[pos++];
      tagNum = tagNum * 128 + (b & 0x7f);
    } while (b & 0x80);
  }
  if (pos >= limit) throw new Asn1Error('ASN.1: truncated length');
  let len = buf[pos++];
  let indefinite = false;
  if (len === 0x80) {
    if (!constructed) throw new Asn1Error('ASN.1: indefinite length on primitive');
    indefinite = true;
    len = -1;
  } else if (len & 0x80) {
    const n = len & 0x7f;
    if (n > 4) throw new Asn1Error('ASN.1: length too long');
    len = 0;
    for (let i = 0; i < n; i++) {
      if (pos >= limit) throw new Asn1Error('ASN.1: truncated length');
      len = len * 256 + buf[pos++];
    }
  }
  const headerLen = pos - start;
  if (!indefinite) {
    if (pos + len > limit) throw new Asn1Error('ASN.1: content exceeds buffer');
    const node = new Node(buf, start, headerLen, len, cls, constructed, tagNum, false);
    if (constructed) {
      node.children = [];
      let p = pos;
      const end = pos + len;
      while (p < end) {
        const ch = parseNode(buf, p, end, depth + 1);
        node.children.push(ch);
        p = ch.end;
      }
    }
    return node;
  }
  // indefinite length: parse children until end-of-contents 00 00
  const children = [];
  let p = pos;
  for (;;) {
    if (p + 2 > limit) throw new Asn1Error('ASN.1: missing end-of-contents');
    if (buf[p] === 0 && buf[p + 1] === 0) break;
    const ch = parseNode(buf, p, limit, depth + 1);
    children.push(ch);
    p = ch.end;
  }
  const node = new Node(buf, start, headerLen, p - pos, cls, constructed, tagNum, true);
  node.children = children;
  return node;
}

/** Parse one ASN.1 element. By default requires the whole buffer to be consumed. */
export function decode(bytes, { allowTrailing = false } = {}) {
  if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
  const node = parseNode(bytes, 0, bytes.length, 0);
  if (!allowTrailing && node.end !== bytes.length) throw new Asn1Error('ASN.1: trailing data');
  return node;
}

// ------------------------------------------------------------------ encoder

function encodeLength(len) {
  if (len < 0x80) return new Uint8Array([len]);
  const bytes = [];
  while (len > 0) {
    bytes.unshift(len & 0xff);
    len = Math.floor(len / 256);
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function encodeTag(cls, constructed, tagNum) {
  if (tagNum < 31) return new Uint8Array([(cls << 6) | (constructed ? 0x20 : 0) | tagNum]);
  const bytes = [];
  let n = tagNum;
  bytes.unshift(n & 0x7f);
  n = Math.floor(n / 128);
  while (n > 0) {
    bytes.unshift((n & 0x7f) | 0x80);
    n = Math.floor(n / 128);
  }
  return new Uint8Array([(cls << 6) | (constructed ? 0x20 : 0) | 0x1f, ...bytes]);
}

export function tlv(cls, constructed, tagNum, content) {
  return concat(encodeTag(cls, constructed, tagNum), encodeLength(content.length), content);
}

function encodeOid(oid) {
  const parts = oid.split('.').map((x) => BigInt(x));
  if (parts.length < 2) throw new Asn1Error('bad OID ' + oid);
  const out = [];
  const pushBase128 = (v) => {
    const tmp = [Number(v & 0x7fn)];
    v >>= 7n;
    while (v > 0n) {
      tmp.unshift(Number(v & 0x7fn) | 0x80);
      v >>= 7n;
    }
    out.push(...tmp);
  };
  pushBase128(parts[0] * 40n + parts[1]);
  for (let i = 2; i < parts.length; i++) pushBase128(parts[i]);
  return new Uint8Array(out);
}

function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

function pad2(n) {
  return String(n).padStart(2, '0');
}

export const der = {
  seq: (...items) => tlv(0, true, TAG.SEQUENCE, concat(...items.filter(Boolean))),
  /** DER SET OF: elements sorted by encoding. */
  set: (...items) => tlv(0, true, TAG.SET, concat(...items.filter(Boolean).slice().sort(compareBytes))),
  /** SET with elements in given order (BER / explicitly ordered). */
  setUnsorted: (...items) => tlv(0, true, TAG.SET, concat(...items.filter(Boolean))),
  int(v) {
    if (v instanceof Uint8Array) {
      // unsigned magnitude -> minimal two's complement
      let i = 0;
      while (i < v.length - 1 && v[i] === 0 && !(v[i + 1] & 0x80)) i++;
      let c = v.subarray(i);
      if (c.length === 0) c = new Uint8Array([0]);
      if (c[0] & 0x80) c = concat(new Uint8Array([0]), c);
      return tlv(0, false, TAG.INTEGER, c);
    }
    const n = BigInt(v);
    if (n < 0n) {
      // two's complement for negatives
      let bytesLen = 1;
      while (-(1n << BigInt(bytesLen * 8 - 1)) > n) bytesLen++;
      const m = (1n << BigInt(bytesLen * 8)) + n;
      const hex = m.toString(16).padStart(bytesLen * 2, '0');
      const out = new Uint8Array(bytesLen);
      for (let i = 0; i < bytesLen; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
      return tlv(0, false, TAG.INTEGER, out);
    }
    return tlv(0, false, TAG.INTEGER, bigIntToJavaBytes(n));
  },
  bool: (b) => tlv(0, false, TAG.BOOLEAN, new Uint8Array([b ? 0xff : 0])),
  null: () => new Uint8Array([5, 0]),
  oid: (oid) => tlv(0, false, TAG.OID, encodeOid(oid)),
  octet: (bytes) => tlv(0, false, TAG.OCTET_STRING, bytes),
  bit: (bytes, unused = 0) => tlv(0, false, TAG.BIT_STRING, concat(new Uint8Array([unused]), bytes)),
  utf8: (s) => tlv(0, false, TAG.UTF8, utf8Encode(s)),
  printable: (s) => tlv(0, false, TAG.PRINTABLE, new Uint8Array([...s].map((c) => c.charCodeAt(0)))),
  ia5: (s) => tlv(0, false, TAG.IA5, new Uint8Array([...s].map((c) => c.charCodeAt(0) & 0x7f))),
  bmp(s) {
    const out = new Uint8Array(s.length * 2);
    for (let i = 0; i < s.length; i++) {
      out[i * 2] = s.charCodeAt(i) >> 8;
      out[i * 2 + 1] = s.charCodeAt(i) & 0xff;
    }
    return tlv(0, false, TAG.BMP, out);
  },
  utcTime(d) {
    const s = pad2(d.getUTCFullYear() % 100) + pad2(d.getUTCMonth() + 1) + pad2(d.getUTCDate()) + pad2(d.getUTCHours()) + pad2(d.getUTCMinutes()) + pad2(d.getUTCSeconds()) + 'Z';
    return tlv(0, false, TAG.UTC_TIME, new Uint8Array([...s].map((c) => c.charCodeAt(0))));
  },
  generalizedTime(d) {
    const s = String(d.getUTCFullYear()).padStart(4, '0') + pad2(d.getUTCMonth() + 1) + pad2(d.getUTCDate()) + pad2(d.getUTCHours()) + pad2(d.getUTCMinutes()) + pad2(d.getUTCSeconds()) + 'Z';
    return tlv(0, false, TAG.GENERALIZED_TIME, new Uint8Array([...s].map((c) => c.charCodeAt(0))));
  },
  /** RFC 5280 Time: UTCTime until 2049, GeneralizedTime afterwards. */
  time(d) {
    const y = d.getUTCFullYear();
    return y >= 1950 && y < 2050 ? der.utcTime(d) : der.generalizedTime(d);
  },
  /** [n] EXPLICIT (constructed context tag wrapping already-encoded elements). */
  explicit: (n, ...items) => tlv(2, true, n, concat(...items)),
  /** [n] IMPLICIT primitive. */
  implicitPrim: (n, content) => tlv(2, false, n, content),
  /** [n] IMPLICIT constructed (content = concatenated encoded children). */
  implicitCons: (n, content) => tlv(2, true, n, content),
  raw: (bytes) => bytes,
};

/** Re-tag an encoded element: replaces its outer tag with the given one (keeps content). Used for IMPLICIT tagging of SET/SEQUENCE. */
export function retag(encoded, cls, constructed, tagNum) {
  const node = decode(encoded);
  return tlv(cls, constructed, tagNum, node.content);
}

/** Debug printer. */
export function dump(node, indent = '') {
  let s = `${indent}[${node.cls}:${node.tagNum}${node.constructed ? ' c' : ''}] len=${node.len}`;
  if (!node.constructed) {
    if (node.isUniversal(TAG.OID)) s += ' ' + node.toOid();
    else if (node.isUniversal(TAG.INTEGER)) s += ' ' + node.toBigInt().toString(16);
    else if ([TAG.UTF8, TAG.PRINTABLE, TAG.IA5, TAG.BMP].includes(node.tagNum) && node.cls === 0) s += ' "' + node.toStr() + '"';
    else s += ' ' + toHex(node.content.subarray(0, 32)) + (node.len > 32 ? '…' : '');
  }
  s += '\n';
  if (node.children) for (const c of node.children) s += dump(c, indent + '  ');
  return s;
}
