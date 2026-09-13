// Signy — MAIN world shim. Runs at document_start in the page's own JavaScript context.
// Replaces connections to the local NCALayer WebSocket server (wss://127.0.0.1:13579) with an in-page
// virtual socket that talks to the Signy extension. Nothing is listening on localhost and no TLS
// certificate is involved. All other WebSocket connections are passed through untouched.
(() => {
  'use strict';
  if (window.__signyNcaShim) return;
  Object.defineProperty(window, '__signyNcaShim', { value: true, enumerable: false });

  const TAG = '__signy_ncalayer__';
  const NCA_RE = /^(wss?|https?):\/\/(127\.0\.0\.1|localhost|\[::1\]):(13579)(\/.*)?$/i;
  const VERSION_MESSAGE = '{"result":{"version":"1.4"}}';
  const HEARTBEAT = '--heartbeat--';

  const NativeWebSocket = window.WebSocket;
  const NativeEventTarget = window.EventTarget;
  const nativeFetch = window.fetch;
  const post = (msg) => window.postMessage({ [TAG]: 'page', ...msg }, window.location.origin === 'null' ? '*' : window.location.origin);

  const sockets = new Map();
  let seq = 0;

  function isNcaUrl(u) {
    try {
      const s = String(u);
      return NCA_RE.test(s);
    } catch {
      return false;
    }
  }

  function defineHandlerProp(obj, name, state) {
    let current = null;
    let wrapper = null;
    Object.defineProperty(obj, 'on' + name, {
      configurable: true,
      enumerable: true,
      get: () => current,
      set: (fn) => {
        if (wrapper) NativeEventTarget.prototype.removeEventListener.call(obj, name, wrapper);
        current = typeof fn === 'function' ? fn : null;
        wrapper = current ? (ev) => current.call(obj, ev) : null;
        if (wrapper) NativeEventTarget.prototype.addEventListener.call(obj, name, wrapper);
      },
    });
  }

  function makeVirtualSocket(url, newTarget) {
    // A genuine EventTarget whose prototype is WebSocket.prototype (instanceof WebSocket === true).
    const ws = Reflect.construct(NativeEventTarget, [], newTarget || PatchedWebSocket);
    const id = 's' + Date.now().toString(36) + '_' + ++seq;
    const state = { id, readyState: 0, url: String(url), binaryType: 'blob', ws };
    sockets.set(id, state);
    const ro = (name, get) => Object.defineProperty(ws, name, { configurable: true, enumerable: true, get });
    ro('url', () => state.url);
    ro('readyState', () => state.readyState);
    ro('bufferedAmount', () => 0);
    ro('extensions', () => '');
    ro('protocol', () => '');
    Object.defineProperty(ws, 'binaryType', { configurable: true, enumerable: true, get: () => state.binaryType, set: (v) => { if (v === 'blob' || v === 'arraybuffer') state.binaryType = v; } });
    for (const ev of ['open', 'message', 'error', 'close']) defineHandlerProp(ws, ev, state);
    Object.defineProperty(ws, 'send', {
      configurable: true,
      value: function send(data) {
        if (state.readyState === 0) throw new DOMException("Failed to execute 'send' on 'WebSocket': Still in CONNECTING state.", 'InvalidStateError');
        if (state.readyState !== 1) return;
        const text = typeof data === 'string' ? data : null;
        if (text === null) {
          // NCALayer only speaks text frames
          return;
        }
        if (text === HEARTBEAT) {
          setTimeout(() => deliver(state, HEARTBEAT), 0);
          return;
        }
        post({ type: 'send', id, data: text });
      },
    });
    Object.defineProperty(ws, 'close', {
      configurable: true,
      value: function close(code, reason) {
        if (state.readyState >= 2) return;
        state.readyState = 2;
        post({ type: 'close', id });
        setTimeout(() => finish(state, code === undefined ? 1005 : code, reason || '', true), 0);
      },
    });
    // connect asynchronously like a real socket
    post({ type: 'open', id, url: state.url });
    state.openTimer = setTimeout(() => {
      // bridge did not answer: extension not available in this frame
      fail(state);
    }, 4000);
    return ws;
  }

  function dispatch(state, event) {
    try {
      NativeEventTarget.prototype.dispatchEvent.call(state.ws, event);
    } catch (e) {
      setTimeout(() => {
        throw e;
      });
    }
  }

  function deliver(state, data) {
    if (state.readyState !== 1) return;
    dispatch(state, new MessageEvent('message', { data, origin: 'wss://127.0.0.1:13579' }));
  }

  function finish(state, code, reason, wasClean) {
    if (state.readyState === 3) return;
    state.readyState = 3;
    sockets.delete(state.id);
    dispatch(state, new CloseEvent('close', { code, reason, wasClean }));
  }

  function fail(state) {
    if (state.readyState === 3) return;
    clearTimeout(state.openTimer);
    dispatch(state, new Event('error'));
    finish(state, 1006, '', false);
  }

  window.addEventListener('message', (e) => {
    if (e.source !== window || !e.data || e.data[TAG] !== 'ext') return;
    const m = e.data;
    const state = sockets.get(m.id);
    if (!state) return;
    switch (m.type) {
      case 'opened':
        clearTimeout(state.openTimer);
        if (state.readyState !== 0) return;
        state.readyState = 1;
        dispatch(state, new Event('open'));
        setTimeout(() => deliver(state, VERSION_MESSAGE), 0);
        break;
      case 'message':
        deliver(state, m.data);
        break;
      case 'error':
        fail(state);
        break;
      case 'closed':
        finish(state, m.code || 1006, m.reason || '', !!m.clean);
        break;
      default:
        break;
    }
  });

  const PatchedWebSocket = new Proxy(NativeWebSocket, {
    construct(target, args, newTarget) {
      if (args.length && isNcaUrl(args[0])) return makeVirtualSocket(args[0], newTarget === PatchedWebSocket ? PatchedWebSocket : newTarget);
      return Reflect.construct(target, args, newTarget === PatchedWebSocket ? target : newTarget);
    },
  });
  try {
    Object.defineProperty(window, 'WebSocket', { configurable: true, writable: true, enumerable: false, value: PatchedWebSocket });
  } catch {
    window.WebSocket = PatchedWebSocket;
  }

  // HTTP(S) probes of the local NCALayer web server (e.g. fetch('https://127.0.0.1:13579/', {mode:'no-cors'}))
  if (typeof nativeFetch === 'function') {
    const patchedFetch = function fetch(input, init) {
      try {
        const u = typeof input === 'string' ? input : input && input.url;
        if (u && isNcaUrl(u)) {
          return Promise.resolve(new Response('NCALayer (Signy)', { status: 200, headers: { 'Content-Type': 'text/plain' } }));
        }
      } catch {
        /* fall through */
      }
      return nativeFetch.apply(this, arguments);
    };
    try {
      Object.defineProperty(patchedFetch, 'toString', { value: () => 'function fetch() { [native code] }' });
      window.fetch = patchedFetch;
    } catch {
      /* ignore */
    }
  }

  // Chrome Local Network Access: nothing is actually requested from localhost, so report "granted"
  // for the loopback permission to clients that check it before connecting.
  try {
    const perms = navigator.permissions;
    if (perms && typeof perms.query === 'function') {
      const nativeQuery = perms.query.bind(perms);
      const lna = new Set(['loopback-network', 'local-network-access', 'local-network']);
      const patchedQuery = function query(desc) {
        if (desc && lna.has(desc.name)) {
          const status = Object.create(NativeEventTarget.prototype);
          Object.defineProperties(status, { state: { value: 'granted', enumerable: true }, name: { value: desc.name, enumerable: true }, onchange: { value: null, writable: true, enumerable: true } });
          return Promise.resolve(status);
        }
        return nativeQuery(desc);
      };
      Object.defineProperty(Permissions.prototype, 'query', { configurable: true, writable: true, value: patchedQuery });
    }
  } catch {
    /* ignore */
  }
})();
