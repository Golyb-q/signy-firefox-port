// Signy — ISOLATED world bridge between the page shim (inject.js) and the extension service worker.
// Keeps one request in flight per virtual socket (NCALayer processes a connection's messages sequentially)
// and holds the payload of interactive requests until the signing window asks for it.
(() => {
  'use strict';
  if (window.__signyBridge) return;
  window.__signyBridge = true;

  const TAG = '__signy_ncalayer__';
  const targetOrigin = window.location.origin === 'null' ? '*' : window.location.origin;
  const toPage = (msg) => window.postMessage({ [TAG]: 'ext', ...msg }, targetOrigin);

  /** socketId -> { queue: string[], busy: boolean, closed: boolean } */
  const sockets = new Map();
  /** requestId -> { socketId, payload } */
  const pending = new Map();

  function alive() {
    try {
      return !!chrome.runtime && !!chrome.runtime.id;
    } catch {
      return false;
    }
  }

  function send(msg) {
    return new Promise((resolve, reject) => {
      if (!alive()) return reject(new Error('extension context invalidated'));
      try {
        chrome.runtime.sendMessage(msg, (resp) => {
          const err = chrome.runtime.lastError;
          if (err) reject(new Error(err.message));
          else resolve(resp);
        });
      } catch (e) {
        reject(e);
      }
    });
  }

  async function pump(socketId) {
    const s = sockets.get(socketId);
    if (!s || s.busy || s.closed || !s.queue.length) return;
    s.busy = true;
    const payload = s.queue.shift();
    try {
      const resp = await send({ type: 'ncl-request', socketId, payload, frameUrl: location.href });
      if (!resp) throw new Error('no response');
      if (resp.pending) {
        pending.set(resp.pending, { socketId, payload });
        return; // released when the signing window answers
      }
      if (resp.response !== undefined && resp.response !== null) toPage({ type: 'message', id: socketId, data: resp.response });
      s.busy = false;
      pump(socketId);
    } catch (e) {
      // extension unavailable (updated/disabled): behave like a dropped connection
      s.busy = false;
      toPage({ type: 'closed', id: socketId, code: 1006, reason: '', clean: false });
      sockets.delete(socketId);
    }
  }

  window.addEventListener('message', async (e) => {
    // accept only messages posted by this very window (blocks spoofing from other frames)
    if (e.source !== window || !e.data || e.data[TAG] !== 'page') return;
    const m = e.data;
    if (typeof m.id !== 'string') return;
    switch (m.type) {
      case 'open': {
        let ok = false;
        try {
          const r = await send({ type: 'ncl-open', socketId: m.id, url: String(m.url || ''), frameUrl: location.href });
          ok = !!(r && r.ok);
        } catch {
          ok = false;
        }
        if (ok) {
          sockets.set(m.id, { queue: [], busy: false, closed: false });
          toPage({ type: 'opened', id: m.id });
        } else {
          toPage({ type: 'error', id: m.id });
        }
        break;
      }
      case 'send': {
        const s = sockets.get(m.id);
        if (!s || typeof m.data !== 'string') return;
        if (m.data.length > 200 * 1024 * 1024) return;
        s.queue.push(m.data);
        pump(m.id);
        break;
      }
      case 'close': {
        const s = sockets.get(m.id);
        if (s) s.closed = true;
        sockets.delete(m.id);
        for (const [rid, p] of pending) {
          if (p.socketId === m.id) {
            pending.delete(rid);
            send({ type: 'ncl-abort', requestId: rid }).catch(() => {});
          }
        }
        break;
      }
      default:
        break;
    }
  });

  if (alive()) {
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (!msg || sender.id !== chrome.runtime.id) return false;
      if (msg.type === 'signy-get-payload') {
        const p = pending.get(msg.requestId);
        sendResponse(p ? { payload: p.payload, origin: location.origin } : { error: 'not-found' });
        return false;
      }
      if (msg.type === 'signy-response') {
        const p = pending.get(msg.requestId);
        if (!p) {
          sendResponse({ ok: false });
          return false;
        }
        pending.delete(msg.requestId);
        const s = sockets.get(p.socketId);
        if (s && !s.closed && msg.response !== null && msg.response !== undefined) toPage({ type: 'message', id: p.socketId, data: msg.response });
        if (s) {
          s.busy = false;
          pump(p.socketId);
        }
        sendResponse({ ok: true });
        return false;
      }
      if (msg.type === 'signy-ping') {
        sendResponse({ ok: true, sockets: sockets.size, pending: pending.size });
        return false;
      }
      return false;
    });
  }
})();
