// Minimal NCALayer client used by the test harness and the automated E2E tests.
// It follows the patterns of real clients (official basics demo, sigex ncalayer-js-client).
(function () {
  const log = document.getElementById('log');
  const status = document.getElementById('status');
  let ws = null;
  let version = null;
  const waiting = [];
  window.__results = [];

  function write(cls, text) {
    const d = document.createElement('div');
    d.className = cls;
    d.textContent = new Date().toLocaleTimeString() + '  ' + text;
    log.prepend(d);
  }

  function connect() {
    return new Promise((resolve, reject) => {
      if (ws && ws.readyState === WebSocket.OPEN) return resolve(ws);
      ws = new WebSocket('wss://127.0.0.1:13579/');
      let first = true;
      ws.onopen = () => {
        status.textContent = 'соединение открыто, ждём версию…';
      };
      ws.onerror = () => {
        status.textContent = 'ошибка подключения (NCALayer/Signy недоступен)';
        write('err', 'WebSocket error');
        reject(new Error('connect failed'));
      };
      ws.onclose = (e) => {
        status.textContent = 'закрыто (' + e.code + ')';
      };
      ws.onmessage = (m) => {
        if (first) {
          first = false;
          try {
            version = JSON.parse(m.data).result.version;
            status.textContent = 'подключено, NCALayer ' + version;
            write('ok', '← ' + m.data);
            window.__ncalayerVersion = version;
            resolve(ws);
          } catch (e) {
            reject(e);
          }
          return;
        }
        write('ok', '← ' + (m.data.length > 600 ? m.data.slice(0, 600) + '… (' + m.data.length + ' симв.)' : m.data));
        let parsed = m.data;
        try { parsed = JSON.parse(m.data); } catch (e) { /* heartbeat */ }
        window.__results.push(parsed);
        const w = waiting.shift();
        if (w) w(parsed);
      };
    });
  }

  async function call(msg) {
    const s = await connect();
    const text = typeof msg === 'string' ? msg : JSON.stringify(msg);
    write('', '→ ' + (text.length > 300 ? text.slice(0, 300) + '…' : text));
    return new Promise((resolve) => {
      waiting.push(resolve);
      s.send(text);
    });
  }
  window.__call = call;

  const b64 = (s) => btoa(unescape(encodeURIComponent(s)));
  const val = (id) => document.getElementById(id).value;
  const chain = () => (document.getElementById('testChain').checked ? [] : null);
  const CU = 'kz.gov.pki.knca.commonUtils';
  const BASICS = 'kz.gov.pki.knca.basics';

  const cmds = {
    getActiveTokens: () => call({ module: CU, method: 'getActiveTokens' }),
    getKeyInfo: () => call({ module: CU, method: 'getKeyInfo', args: ['PKCS12'] }),
    signXml: () => call({ module: CU, method: 'signXml', args: ['PKCS12', 'SIGNATURE', val('xml'), '', ''] }),
    signXmlAuth: () => call({ module: CU, method: 'signXml', args: ['PKCS12', 'AUTHENTICATION', val('xml'), '', ''] }),
    signXmls: () => call({ module: CU, method: 'signXmls', args: ['PKCS12', 'SIGNATURE', [val('xml'), '<doc2><a>2</a></doc2>'], '', ''] }),
    createCAdESFromBase64: () => call({ module: CU, method: 'createCAdESFromBase64', args: ['PKCS12', 'SIGNATURE', b64(val('data')), true] }),
    createCMSSignatureFromBase64: () => call({ module: CU, method: 'createCMSSignatureFromBase64', args: ['PKCS12', 'SIGNATURE', b64(val('data')), false] }),
    createCAdESFromBase64Hash: async () => {
      const h = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(val('data'))));
      return call({ module: CU, method: 'createCAdESFromBase64Hash', args: ['PKCS12', 'SIGNATURE', btoa(String.fromCharCode(...h))] });
    },
    changeLocale: () => call({ module: CU, method: 'changeLocale', args: ['ru'] }),
    basicsXml: () => call({ module: BASICS, method: 'sign', args: { allowedStorages: ['PKCS12'], format: 'xml', data: val('xml'), signingParams: {}, signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.4'], chain: chain() }, locale: 'ru' } }),
    basicsXmlAuth: () => call({ module: BASICS, method: 'sign', args: { allowedStorages: ['PKCS12'], format: 'xml', data: val('xml'), signingParams: {}, signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'], chain: chain() }, locale: 'ru' } }),
    basicsCms: () => call({ module: BASICS, method: 'sign', args: { format: 'cms', data: b64(val('data')), signingParams: { decode: true, encapsulate: false, digested: false }, signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.4'], chain: chain() }, locale: 'ru' } }),
    basicsCmsTsp: () => call({ module: BASICS, method: 'sign', args: { format: 'cms', data: b64(val('data')), signingParams: { decode: true, encapsulate: false, digested: false, tsaProfile: {} }, signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.4'], chain: chain() }, locale: 'ru' } }),
    basicsMulti: () => call({ module: BASICS, method: 'sign', args: { format: 'cms', data: [b64('документ 1'), b64('документ 2'), b64('документ 3')], signingParams: { decode: true, encapsulate: true }, signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.4'], chain: chain() }, locale: 'kk' } }),
    basicsRaw: () => call({ module: BASICS, method: 'sign', args: { format: 'raw', data: b64(val('data')), signingParams: { decode: true, outputCert: true }, signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.4'], chain: chain() }, locale: 'ru' } }),
    heartbeat: () => call('--heartbeat--'),
    unknownModule: () => call({ module: 'kz.example.unknown', method: 'x' }),
    probe: async () => {
      try {
        await fetch('https://127.0.0.1:13579/', { mode: 'no-cors', cache: 'no-store' });
        write('ok', 'probe: доступен');
      } catch (e) {
        write('err', 'probe: ' + e.message);
      }
    },
  };
  window.__cmds = cmds;

  document.getElementById('connect').onclick = () => connect().catch(() => {});
  document.querySelectorAll('button[data-cmd]').forEach((b) => {
    b.onclick = () => cmds[b.dataset.cmd]().catch((e) => write('err', String(e)));
  });
})();
