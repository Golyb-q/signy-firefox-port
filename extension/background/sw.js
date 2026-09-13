// Signy service worker: receives NCALayer protocol messages from pages (via content/bridge.js), answers the
// non-interactive ones and opens the signing window for the rest. It is stateless apart from small records in
// chrome.storage.session, so it can be suspended at any time (MV3).
import { parseRequest, routeRequest, cancelResponse, MODULE } from '../lib/ncalayer/protocol.js';
import { getSettings, originAllowed } from '../lib/settings.js';

const REQ_PREFIX = 'req:';
const SIGNER_W = 580;
const SIGNER_H = 780;

function originOf(sender, fallbackUrl) {
  if (sender.origin && sender.origin !== 'null') return sender.origin;
  try {
    return new URL(sender.url || fallbackUrl).origin;
  } catch {
    return 'null';
  }
}

function newId() {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

async function allRecords() {
  const all = await chrome.storage.session.get(null);
  return Object.entries(all).filter(([k]) => k.startsWith(REQ_PREFIX)).map(([, v]) => v);
}

async function saveRecord(rec) {
  await chrome.storage.session.set({ [REQ_PREFIX + rec.id]: rec });
}

async function dropRecord(id) {
  await chrome.storage.session.remove(REQ_PREFIX + id);
}

async function openSignerWindow(rec, sender) {
  let left;
  let top;
  try {
    if (sender.tab && sender.tab.windowId !== undefined) {
      const w = await chrome.windows.get(sender.tab.windowId);
      left = Math.max(0, Math.round(w.left + (w.width - SIGNER_W) / 2));
      top = Math.max(0, Math.round(w.top + Math.min(120, (w.height - SIGNER_H) / 2)));
    }
  } catch {
    /* default placement */
  }
  const win = await chrome.windows.create({
    url: chrome.runtime.getURL('signer/signer.html?id=' + rec.id),
    type: 'popup',
    width: SIGNER_W,
    height: SIGNER_H,
    left,
    top,
    focused: true,
  });
  return win.id;
}

async function handleRequest(msg, sender) {
  const origin = originOf(sender, msg.frameUrl);
  const settings = await getSettings();
  if (!originAllowed(settings, origin)) return { response: null, closed: true };
  const req = parseRequest(msg.payload);
  const route = routeRequest(req);
  switch (route.kind) {
    case 'immediate':
      return { response: route.response };
    case 'noreply':
    case 'ignore':
      return { response: null };
    case 'accessory':
      chrome.runtime.openOptionsPage();
      return { response: JSON.stringify({ status: true, body: {} }) };
    case 'interactive': {
      const rec = {
        id: newId(),
        tabId: sender.tab ? sender.tab.id : -1,
        frameId: sender.frameId || 0,
        socketId: msg.socketId,
        origin,
        pageUrl: sender.url || msg.frameUrl || '',
        tabTitle: sender.tab ? sender.tab.title || '' : '',
        module: route.module,
        method: route.method,
        uuid: req.uuid || '',
        cancel: route.cancel || cancelResponse(route.module, route.method, req.uuid),
        createdAt: Date.now(),
        windowId: null,
      };
      await saveRecord(rec);
      try {
        rec.windowId = await openSignerWindow(rec, sender);
        await saveRecord(rec);
      } catch (e) {
        await dropRecord(rec.id);
        return { response: rec.cancel };
      }
      return { pending: rec.id };
    }
    default:
      return { response: null };
  }
}

async function sendToTab(rec, response) {
  if (rec.tabId < 0) return;
  try {
    await chrome.tabs.sendMessage(rec.tabId, { type: 'signy-response', requestId: rec.id, response }, { frameId: rec.frameId });
  } catch {
    /* tab gone */
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg !== 'object' || sender.id !== chrome.runtime.id) return false;
  switch (msg.type) {
    case 'ncl-open':
      (async () => {
        const settings = await getSettings();
        sendResponse({ ok: originAllowed(settings, originOf(sender, msg.frameUrl)) });
      })();
      return true;
    case 'ncl-request':
      handleRequest(msg, sender).then(sendResponse, (e) => sendResponse({ response: null, error: String(e) }));
      return true;
    case 'ncl-abort':
      (async () => {
        const rec = (await chrome.storage.session.get(REQ_PREFIX + msg.requestId))[REQ_PREFIX + msg.requestId];
        if (rec) {
          await dropRecord(rec.id);
          if (rec.windowId) chrome.windows.remove(rec.windowId).catch(() => {});
        }
        sendResponse({ ok: true });
      })();
      return true;
    case 'signer-finished':
      // the signing window already delivered its response to the tab
      dropRecord(msg.requestId).then(() => sendResponse({ ok: true }));
      return true;
    default:
      return false;
  }
});

chrome.windows.onRemoved.addListener(async (windowId) => {
  for (const rec of await allRecords()) {
    if (rec.windowId === windowId) {
      await dropRecord(rec.id);
      await sendToTab(rec, rec.cancel || cancelResponse(rec.module, rec.method, rec.uuid));
    }
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  for (const rec of await allRecords()) {
    if (rec.tabId === tabId) {
      await dropRecord(rec.id);
      if (rec.windowId) chrome.windows.remove(rec.windowId).catch(() => {});
    }
  }
});

// ---------------------------------------------------------------- user-approved extra sites

async function syncExtraContentScripts() {
  const settings = await getSettings();
  const ids = ['signy-extra-main', 'signy-extra-bridge'];
  try {
    await chrome.scripting.unregisterContentScripts({ ids });
  } catch {
    /* none registered */
  }
  const matches = settings.extraOrigins.map((o) => o.replace(/\/$/, '') + '/*');
  if (!matches.length) return;
  const granted = [];
  for (const m of matches) if (await chrome.permissions.contains({ origins: [m] })) granted.push(m);
  if (!granted.length) return;
  await chrome.scripting.registerContentScripts([
    { id: ids[0], matches: granted, js: ['content/inject.js'], runAt: 'document_start', allFrames: true, matchOriginAsFallback: true, world: 'MAIN', persistAcrossSessions: true },
    { id: ids[1], matches: granted, js: ['content/bridge.js'], runAt: 'document_start', allFrames: true, matchOriginAsFallback: true, persistAcrossSessions: true },
  ]);
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.settings) syncExtraContentScripts().catch(() => {});
});
chrome.permissions.onAdded.addListener(() => syncExtraContentScripts().catch(() => {}));
chrome.permissions.onRemoved.addListener(() => syncExtraContentScripts().catch(() => {}));
chrome.runtime.onInstalled.addListener(() => {
  syncExtraContentScripts().catch(() => {});
  chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }).catch(() => {});
});
chrome.runtime.onStartup.addListener(() => syncExtraContentScripts().catch(() => {}));

export { MODULE };
