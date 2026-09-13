// Formatting helpers for certificates in the UI.
import { kncaCertTypes } from '../lib/ncalayer/certcheck.js';

export function fmtDate(d) {
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()}`;
}

export function familyLabel(cert, t) {
  switch (cert.keyFamily) {
    case 'GOST2015_512':
      return t('gost2015');
    case 'GOST2004':
      return t('gost2004');
    case 'RSA':
      return t('rsa');
    default:
      return cert.keyFamily;
  }
}

export function certSummary(cert) {
  const sn = cert.subjectAttr('2.5.4.5') || '';
  const ou = cert.subjectAttr('2.5.4.11') || '';
  const types = kncaCertTypes(cert);
  return {
    cn: cert.subjectCn || '',
    iin: sn.startsWith('IIN') ? sn.slice(3) : '',
    bin: ou.startsWith('BIN') ? ou.slice(3) : '',
    org: cert.subjectAttr('2.5.4.10') || '',
    issuer: cert.issuerCn || '',
    notBefore: cert.notBefore.getTime(),
    notAfter: cert.notAfter.getTime(),
    family: cert.keyFamily,
    types: [...types],
    serial: cert.serialHex,
  };
}

export function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

export function applyTranslations(root, t) {
  for (const n of root.querySelectorAll('[data-t]')) n.textContent = t(n.getAttribute('data-t'));
  for (const n of root.querySelectorAll('[data-t-title]')) {
    n.title = t(n.getAttribute('data-t-title'));
    n.setAttribute('aria-label', n.title);
  }
}
