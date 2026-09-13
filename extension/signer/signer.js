// Signing window controller. Runs entirely inside the extension: the private key is decrypted here, used for the
// requested operation and dropped; nothing is sent anywhere except the NCALayer-format response to the page
// (and, when the site asks for a timestamp, the signature hash to tsp.pki.gov.kz).
import { parseRequest, cancelResponse, MODULE } from '../lib/ncalayer/protocol.js';
import { describeOperation, entryStatus, executeOperation, failureResponse, chosenPathResponse } from '../lib/ncalayer/operations.js';
import { parsePkcs12, Pkcs12Error } from '../lib/pkcs12.js';
import { SigningKey } from '../lib/signer.js';
import { getSettings, listKeys, saveKey, removeKey, getSiteHistory, recordSiteUse } from '../lib/settings.js';
import { makeT } from '../lib/i18n.js';
import { toBase64, fromBase64, toHex } from '../lib/util.js';
import { decode } from '../lib/asn1.js';
import { digest } from '../lib/hash/index.js';
import { parsePemList, kncaCertTypes } from '../lib/ncalayer/certcheck.js';
import { fmtDate, familyLabel, certSummary, el, applyTranslations } from '../ui/format.js';

const $ = (id) => document.getElementById(id);

const state = {
  rec: null,
  req: null,
  op: null,
  settings: null,
  t: makeT('ru'),
  locale: 'ru',
  file: null, // { bytes, name, savedId }
  entries: [],
  statuses: [],
  selected: -1,
  busy: false,
  finished: false,
};

// ------------------------------------------------------------------ delivery

async function deliver(response) {
  if (state.finished) return;
  state.finished = true;
  const { rec } = state;
  try {
    await chrome.tabs.sendMessage(rec.tabId, { type: 'signy-response', requestId: rec.id, response }, { frameId: rec.frameId });
  } catch {
    /* page is gone */
  }
  try {
    await chrome.runtime.sendMessage({ type: 'signer-finished', requestId: rec.id });
  } catch {
    /* ignore */
  }
}

function closeSoon(ms = 0) {
  setTimeout(() => window.close(), ms);
}

async function cancel() {
  if (state.busy) return;
  if (state.rec && !state.finished) await deliver(state.rec.cancel || cancelResponse(state.rec.module, state.rec.method, state.rec.uuid));
  closeSoon();
}

// ------------------------------------------------------------------ helpers

function setStatus(text) {
  const s = $('status');
  s.hidden = !text;
  s.textContent = text || '';
}

function showKeyError(text) {
  const e = $('keyError');
  e.hidden = !text;
  e.textContent = text || '';
}

function fatal(text) {
  const f = $('fatal');
  f.hidden = false;
  f.textContent = text;
  $('signBtn').disabled = true;
  $('cancelBtn').textContent = state.t('close');
}

function relTime(ts) {
  return fmtDate(new Date(ts));
}

function isStorageAllowed() {
  const { op } = state;
  if (op.module === MODULE.BASICS) return !op.allowedStorages || op.allowedStorages.includes('PKCS12');
  if (op.module === MODULE.COMMON && op.kind !== 'chooseFile') return !op.storage || op.storage === 'PKCS12' || op.storage === 'JKS';
  if (op.module === MODULE.APPLET && op.kind !== 'chooseFile') return op.storage === 'PKCS12' || op.storage === 'JKS';
  return true;
}

// ------------------------------------------------------------------ rendering

function renderRequest() {
  const { rec, op, t } = state;
  $('request').hidden = false;
  const o = $('origin');
  o.textContent = '';
  let scheme = '';
  let host = rec.origin;
  const m = /^(https?:\/\/)(.*)$/.exec(rec.origin);
  if (m) {
    scheme = m[1];
    host = m[2];
  }
  o.append(el('span', { class: 'scheme', text: scheme }), host);
  if (scheme === 'http://' && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(rec.origin)) o.classList.add('insecure');
  o.title = rec.pageUrl;
  $('opTitle').textContent = op.title;
  const notes = [];
  if (op.kind === 'keyInfo') notes.push(t('keyInfoNote'));
  if (op.kind === 'chooseKeyStore') notes.push(t('keyStoreNote'));
  if (op.purpose === 'auth') notes.push(t('authNote'));
  if (op.cms && op.cms.tsa) notes.push(t('tsaNote'));
  if (notes.length) {
    $('opNote').hidden = false;
    $('opNote').textContent = notes.join(' ');
  }
  if (op.logo) {
    try {
      const b = fromBase64(op.logo);
      let mime = 'image/png';
      if (b[0] === 0xff && b[1] === 0xd8) mime = 'image/jpeg';
      else if (b[0] === 0x47 && b[1] === 0x49) mime = 'image/gif';
      else if (b[0] === 0x3c) mime = 'image/svg+xml';
      $('siteLogo').src = `data:${mime};base64,${toBase64(b)}`;
      $('siteLogo').hidden = false;
    } catch {
      /* ignore bad logo */
    }
  }
}

function prettyXml(xml) {
  if (xml.length > 200000) return xml;
  // display-only indentation; the signed data is the original string
  const tokens = xml.replace(/>\s+</g, '><').split(/(<[^>]+>)/).filter((x) => x.length);
  const lines = [];
  let depth = 0;
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    const isTag = tok.startsWith('<');
    if (isTag && tok.startsWith('</')) {
      depth = Math.max(0, depth - 1);
      lines.push('  '.repeat(depth) + tok);
    } else if (isTag && !tok.startsWith('<?') && !tok.startsWith('<!') && !tok.endsWith('/>')) {
      const text = tokens[i + 1];
      const close = tokens[i + 2];
      if (text !== undefined && !text.startsWith('<') && close && close.startsWith('</')) {
        lines.push('  '.repeat(depth) + tok + text + close);
        i += 2;
      } else {
        lines.push('  '.repeat(depth) + tok);
        depth++;
      }
    } else if (isTag) {
      lines.push('  '.repeat(depth) + tok);
    } else {
      lines.push('  '.repeat(depth) + tok.trim());
    }
  }
  return lines.join('\n');
}

function renderDocs() {
  const { op, t } = state;
  if (!op.items || !op.items.length) return;
  $('dataCard').hidden = false;
  $('docCount').textContent = op.items.length > 1 ? `(${t('documents')}: ${op.items.length})` : '';
  const docs = $('docs');
  docs.textContent = '';
  op.items.forEach((it, i) => {
    const head = el('div', { class: 'doc-head' });
    const body = el('pre', { class: 'doc-body' });
    const actions = el('div', { class: 'doc-actions' });
    let label;
    if (it.xml !== undefined) {
      label = `XML · ${it.size} ${t('bytes')}`;
      body.textContent = prettyXml(it.xml);
    } else if (it.isHash) {
      label = `${t('binaryData')} · ${it.size} ${t('bytes')}`;
      body.textContent = t('hashOnly') + '\n' + toHex(it.bytes);
    } else if (it.isCms) {
      label = `CMS · ${it.size} ${t('bytes')}`;
      body.textContent = 'SHA-256: ' + toHex(digest('SHA-256', it.bytes));
    } else if (it.text !== null && it.text !== undefined) {
      label = `${it.size} ${t('bytes')}`;
      body.textContent = it.text;
    } else {
      label = `${it.isPdf ? t('pdfDocument') : t('binaryData')} · ${it.size} ${t('bytes')}`;
      body.textContent = 'SHA-256: ' + toHex(digest('SHA-256', it.bytes));
      if (it.isPdf) {
        actions.append(el('button', {
          class: 'link-btn',
          type: 'button',
          text: t('openPreview'),
          onclick: () => {
            const url = URL.createObjectURL(new Blob([it.bytes], { type: 'application/pdf' }));
            chrome.tabs.create({ url });
          },
        }));
      }
    }
    const doc = el('div', { class: 'doc' });
    const toggle = el('button', {
      class: 'link-btn',
      type: 'button',
      text: t('showAll'),
      onclick: () => {
        doc.classList.toggle('expanded');
        toggle.textContent = doc.classList.contains('expanded') ? t('collapse') : t('showAll');
      },
    });
    actions.append(toggle);
    head.append(el('span', { text: (op.items.length > 1 ? `#${i + 1} · ` : '') + label }), actions);
    doc.append(head, body);
    docs.append(doc);
  });
}

async function renderSavedKeys() {
  const keys = await listKeys();
  const box = $('savedKeys');
  const list = $('savedList');
  list.textContent = '';
  box.hidden = keys.length === 0;
  for (const k of keys.sort((a, b) => (b.lastUsed || 0) - (a.lastUsed || 0))) {
    const s = (k.summary && k.summary[0]) || {};
    const li = el('li', { tabindex: '0', role: 'button', 'data-id': k.id },
      el('span', { class: 'name' },
        el('div', { class: 'ellipsis', text: s.cn || k.name }),
        el('div', { class: 'sub ellipsis', text: [k.name, s.notAfter ? `${state.t('validTo')} ${relTime(s.notAfter)}` : ''].filter(Boolean).join(' · ') })),
      el('button', {
        class: 'icon-btn',
        type: 'button',
        title: state.t('forget'),
        'aria-label': state.t('forget'),
        text: '✕',
        onclick: async (e) => {
          e.stopPropagation();
          await removeKey(k.id);
          if (state.file && state.file.savedId === k.id) resetFile();
          renderSavedKeys();
        },
      }));
    const select = () => {
      if (state.op.kind === 'chooseKeyStore') {
        deliverKeyStore(fromBase64(k.p12), k.name);
        return;
      }
      for (const n of list.children) n.classList.remove('selected');
      li.classList.add('selected');
      state.file = { bytes: fromBase64(k.p12), name: k.name, savedId: k.id };
      $('fileName').textContent = k.name;
      $('remember').checked = true;
      enablePassword();
    };
    li.addEventListener('click', select);
    li.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        select();
      }
    });
    list.append(li);
    if (keys.length === 1 && !state.file && state.op.kind !== 'chooseKeyStore') select();
  }
}

function resetFile() {
  state.file = null;
  $('fileName').textContent = state.t('noFile');
  $('password').disabled = true;
  $('openBtn').disabled = true;
}

function enablePassword() {
  $('pwForm').hidden = false;
  $('keyOpened').hidden = true;
  $('password').disabled = false;
  $('openBtn').disabled = false;
  $('password').value = '';
  $('password').focus();
  showKeyError('');
  $('certCard').hidden = true;
  state.entries = [];
  state.selected = -1;
  updateSignButton();
}

function describeStatusBadges(entry, st) {
  const { t } = state;
  const c = entry.cert;
  const badges = [el('span', { class: 'badge', text: familyLabel(c, t) })];
  const types = kncaCertTypes(c);
  if (types.has('SIGNATURE')) badges.push(el('span', { class: 'badge', text: t('purposeSign') }));
  if (types.has('AUTHENTICATION')) badges.push(el('span', { class: 'badge', text: t('purposeAuth') }));
  const ci = st.chainInfo;
  if (ci && ci.ok && ci.kind === 'nca') badges.push(el('span', { class: 'badge ok', text: t('chainOk') }));
  else if (ci && ci.ok && ci.kind === 'nca-test') badges.push(el('span', { class: 'badge', text: t('testCa') }));
  else if (ci && ci.ok && ci.kind === 'extra') badges.push(el('span', { class: 'badge', text: t('chainExtra') }));
  else badges.push(el('span', { class: 'badge bad', text: t('chainUnknown') }));
  if (st.expired) badges.push(el('span', { class: 'badge bad', text: t('expired') }));
  return badges;
}

function renderCerts() {
  const { entries, statuses, t } = state;
  const list = $('certList');
  list.textContent = '';
  $('certCard').hidden = false;
  entries.forEach((entry, i) => {
    const st = statuses[i];
    const s = certSummary(entry.cert);
    const radio = el('input', { type: 'radio', name: 'cert', value: String(i), disabled: st.disabled ? true : undefined, 'aria-label': s.cn });
    const li = el('li', { class: 'cert' + (st.disabled ? ' disabled' : ''), role: 'radio', 'aria-disabled': st.disabled ? 'true' : 'false' },
      radio,
      el('div', { class: 'cn', text: s.cn }),
      el('div', { class: 'meta', text: [s.iin && `${t('iin')} ${s.iin}`, s.org && `${t('org')}: ${s.org}`, s.bin && `${t('bin')} ${s.bin}`].filter(Boolean).join(' · ') || ' ' }),
      el('div', { class: 'meta', text: `${t('validTo')} ${fmtDate(entry.cert.notAfter)} · ${t('issuer')}: ${s.issuer}` }),
      el('div', { class: 'badges' }, ...describeStatusBadges(entry, st)),
      st.reasons.length ? el('div', { class: 'why', text: st.reasons.join('; ') }) : null);
    const pick = () => {
      if (st.disabled) return;
      state.selected = i;
      for (const n of list.children) n.classList.remove('selected');
      li.classList.add('selected');
      radio.checked = true;
      updateSignButton();
    };
    li.addEventListener('click', pick);
    radio.addEventListener('change', pick);
    list.append(li);
  });
  const first = statuses.findIndex((s) => !s.disabled);
  if (first >= 0) list.children[first].click();
  else updateSignButton();
}

function updateSignButton() {
  const btn = $('signBtn');
  const { op, t } = state;
  btn.textContent = op && op.kind === 'keyInfo' ? t('choose') : op && op.purpose === 'auth' ? t('signIn') : t('sign');
  btn.disabled = state.busy || state.selected < 0 || state.finished;
}

// ------------------------------------------------------------------ actions

async function openKey(ev) {
  if (ev) ev.preventDefault();
  if (!state.file || state.busy) return;
  const password = $('password').value;
  const { t } = state;
  showKeyError('');
  setStatus(t('opening'));
  state.busy = true;
  $('openBtn').disabled = true;
  try {
    const parsed = await parsePkcs12(state.file.bytes, password);
    state.entries = parsed.entries;
    const extraAnchors = parsePemList(state.settings.extraTrustPem || []);
    state.statuses = state.entries.map((e) => entryStatus(state.op, e, { includeTestCa: state.settings.allowTestCa, extraAnchors }));
    state.password = null;
    $('password').value = '';
    if ($('remember').checked) {
      const id = keyId(state.file.bytes);
      await saveKey({ id, name: state.file.name, size: state.file.bytes.length, addedAt: Date.now(), lastUsed: Date.now(), p12: toBase64(state.file.bytes), summary: state.entries.map((e) => certSummary(e.cert)) });
      state.file.savedId = id;
    }
    setStatus('');
    $('pwForm').hidden = true;
    $('keyOpened').hidden = false;
    $('keyOpenedName').textContent = state.file.name;
    renderCerts();
    $('certCard').scrollIntoView({ block: 'nearest' });
  } catch (e) {
    setStatus('');
    if (e instanceof Pkcs12Error) {
      showKeyError(e.code === 'WRONG_PASSWORD' ? t('wrongPassword') : e.code === 'BAD_FORMAT' ? t('badFile') : e.code === 'NO_KEYS' ? t('noKeys') : e.message);
    } else showKeyError(`${t('errorPrefix')}: ${e.message}`);
    $('password').select();
  } finally {
    state.busy = false;
    $('openBtn').disabled = !state.file;
    updateSignButton();
  }
}

async function doSign() {
  const { op, t } = state;
  if (state.selected < 0 || state.busy || state.finished) return;
  const entry = state.entries[state.selected];
  const st = state.statuses[state.selected];
  if (st.disabled) return;
  if (st.expired && op.module === MODULE.BASICS && !(op.xmlParams && op.xmlParams.allowExpired)) {
    showKeyError(t('expired'));
    return;
  }
  state.busy = true;
  updateSignButton();
  setStatus(t('signing'));
  const signer = new SigningKey(entry);
  try {
    const response = await executeOperation(op, signer, {
      tsaUrl: state.settings.tsaUrl,
      onProgress: (s) => setStatus(s),
      readFile: readChosenFile,
    });
    await deliver(response);
    await recordSiteUse(state.rec.origin);
    if (state.file && state.file.savedId) {
      const keys = await listKeys();
      const k = keys.find((x) => x.id === state.file.savedId);
      if (k) await saveKey({ ...k, lastUsed: Date.now() });
    }
    setStatus(t('done'));
    closeSoon(350);
  } catch (e) {
    console.error(e);
    setStatus('');
    state.busy = false;
    state.lastError = e;
    showKeyError(`${t('errorPrefix')}: ${e.message}`);
    $('cancelBtn').textContent = t('sendError');
    updateSignButton();
  } finally {
    signer.destroy();
    for (const en of state.entries) {
      if (en.key && en !== entry) en.key.d = 0n;
    }
  }
}

async function readChosenFile(path) {
  const m = /^signy-file:([0-9a-f]+)\//.exec(path);
  if (!m) return null;
  const key = 'file:' + m[1];
  const r = await chrome.storage.session.get(key);
  return r[key] ? fromBase64(r[key]) : null;
}

function keyId(bytes) {
  return toHex(digest('SHA-256', bytes)).slice(0, 24);
}

/** Keeps a chosen file for later requests of this browser session; the site only gets a conditional path. */
async function storeChosenFile(bytes, name) {
  const token = toHex(crypto.getRandomValues(new Uint8Array(12)));
  await chrome.storage.session.set({ ['file:' + token]: toBase64(bytes) });
  return `signy-file:${token}/${name}`;
}

async function chooseAnyFile(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length > 7 * 1024 * 1024) {
    fatal('Файл слишком большой (максимум 7 МБ)');
    return;
  }
  await deliver(chosenPathResponse(state.op, await storeChosenFile(bytes, file.name)));
  closeSoon(100);
}

function looksLikePkcs12(bytes) {
  try {
    const pfx = decode(bytes);
    return pfx.child(0).toBigInt() === 3n;
  } catch {
    return false;
  }
}

/** Applet.browseKeyStore: the key file is only chosen here; its password is asked when the site signs with it. */
async function deliverKeyStore(bytes, name) {
  if (state.finished || state.busy) return;
  if (!looksLikePkcs12(bytes)) {
    showKeyError(state.t('badFile'));
    return;
  }
  state.busy = true;
  await deliver(chosenPathResponse(state.op, await storeChosenFile(bytes, name)));
  setStatus(state.t('done'));
  closeSoon(150);
}

/** Applet.signXml(storage, container, ...): preselect the key file the site got from browseKeyStore. */
async function preloadContainer(path) {
  const bytes = await readChosenFile(path);
  if (!bytes) return;
  const id = keyId(bytes);
  const saved = (await listKeys()).find((k) => k.id === id);
  state.file = { bytes, name: saved ? saved.name : path.slice(path.indexOf('/') + 1), savedId: saved ? id : null };
  for (const n of $('savedList').children) n.classList.toggle('selected', n.dataset.id === id);
  $('fileName').textContent = state.file.name;
  if (saved) $('remember').checked = true;
  enablePassword();
}

// ------------------------------------------------------------------ init

async function init() {
  const id = new URLSearchParams(location.search).get('id');
  state.settings = await getSettings();
  const recKey = 'req:' + id;
  const rec = (await chrome.storage.session.get(recKey))[recKey];
  applyTranslations(document, state.t);
  $('cancelBtn').addEventListener('click', cancel);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') cancel();
  });
  if (!rec) {
    fatal(state.t('requestExpired'));
    $('cancelBtn').onclick = () => window.close();
    return;
  }
  state.rec = rec;
  let payloadResp;
  try {
    payloadResp = await chrome.tabs.sendMessage(rec.tabId, { type: 'signy-get-payload', requestId: rec.id }, { frameId: rec.frameId });
  } catch {
    payloadResp = null;
  }
  if (!payloadResp || !payloadResp.payload) {
    fatal(state.t('requestExpired'));
    return;
  }
  state.req = parseRequest(payloadResp.payload);
  try {
    state.op = describeOperation(state.req);
  } catch (e) {
    const opStub = { module: rec.module, method: rec.method, uuid: rec.uuid };
    await deliver(failureResponse(opStub, e));
    fatal(`${state.t('errorPrefix')}: ${e.message}`);
    return;
  }
  const loc = state.settings.uiLocale && state.settings.uiLocale !== 'auto' ? state.settings.uiLocale : state.op.module === MODULE.BASICS ? state.op.locale : 'ru';
  setLocale(loc === 'kk' ? 'kk' : 'ru');
  $('lang').addEventListener('click', () => {
    setLocale(state.locale === 'kk' ? 'ru' : 'kk');
  });

  renderRequest();
  const history = await getSiteHistory();
  if (!history[rec.origin]) $('firstTime').hidden = false;

  if (state.op.kind === 'chooseFile') {
    $('fileCard').hidden = false;
    $('signBtn').hidden = true;
    $('anyFileInput').addEventListener('change', (e) => {
      const f = e.target.files && e.target.files[0];
      if (f) chooseAnyFile(f);
    });
    return;
  }

  renderDocs();
  $('keyCard').hidden = false;
  if (!isStorageAllowed()) {
    $('tokenNote').hidden = false;
    $('fileInput').disabled = true;
    return;
  }
  if (state.op.kind === 'chooseKeyStore') {
    $('pwForm').hidden = true;
    $('signBtn').hidden = true;
    await renderSavedKeys();
    $('fileInput').addEventListener('change', async (e) => {
      const f = e.target.files && e.target.files[0];
      if (!f) return;
      if (f.size > 1024 * 1024) {
        showKeyError(state.t('badFile'));
        return;
      }
      deliverKeyStore(new Uint8Array(await f.arrayBuffer()), f.name);
    });
    return;
  }
  $('remember').checked = !!state.settings.rememberKeysDefault;
  await renderSavedKeys();
  if (state.op.module === MODULE.APPLET && state.op.container) await preloadContainer(state.op.container);
  $('fileInput').addEventListener('change', async (e) => {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    if (f.size > 1024 * 1024) {
      showKeyError(state.t('badFile'));
      return;
    }
    state.file = { bytes: new Uint8Array(await f.arrayBuffer()), name: f.name, savedId: null };
    for (const n of $('savedList').children) n.classList.remove('selected');
    $('fileName').textContent = f.name;
    enablePassword();
  });
  $('pwForm').addEventListener('submit', openKey);
  $('togglePw').addEventListener('click', () => {
    const p = $('password');
    p.type = p.type === 'password' ? 'text' : 'password';
  });
  $('signBtn').addEventListener('click', doSign);
  $('changeKey').addEventListener('click', () => {
    for (const en of state.entries) if (en.key) en.key.d = 0n;
    enablePassword();
  });
  updateSignButton();
}

function setLocale(loc) {
  state.locale = loc;
  state.t = makeT(loc);
  document.documentElement.lang = loc === 'kk' ? 'kk' : 'ru';
  $('lang').textContent = loc === 'kk' ? 'РУС' : 'ҚАЗ';
  applyTranslations(document, state.t);
  if (state.op) {
    updateSignButton();
    if (state.entries.length) renderCerts();
    if (!state.file) $('fileName').textContent = state.t('noFile');
    renderDocs();
  }
}

// If the user closes the window with the OS button the service worker sends the cancel response.
init().catch((e) => {
  console.error(e);
  fatal(`${state.t('errorPrefix')}: ${e.message}`);
});

// Kept for the cancel-after-error path: if signing failed, closing sends the failure to the site.
$('cancelBtn').addEventListener('click', async () => {
  if (state.lastError && !state.finished && state.op) {
    await deliver(failureResponse(state.op, state.lastError));
  }
}, { capture: true });
