// Quick smoke test: extension loads, the page sees "NCALayer 1.4", immediate methods answer.
import { launch, startServer } from './lib.mjs';

const { server, port } = await startServer();
const { context, sw, extensionId } = await launch({ headless: process.env.HEADFUL ? false : true });
console.log('extension id', extensionId);
const page = await context.newPage();
page.on('console', (m) => console.log('[page]', m.type(), m.text()));
await page.goto(`http://localhost:${port}/index.html`);
await page.waitForFunction(() => typeof window.__call === 'function');
const r1 = await page.evaluate(() => window.__call({ module: 'kz.gov.pki.knca.commonUtils', method: 'getActiveTokens' }));
console.log('version', await page.evaluate(() => window.__ncalayerVersion), 'getActiveTokens', JSON.stringify(r1));
const r2 = await page.evaluate(() => window.__call('--heartbeat--'));
console.log('heartbeat', JSON.stringify(r2));
const r3 = await page.evaluate(() => window.__call({ module: 'kz.example.unknown', method: 'x' }));
console.log('unknown module', JSON.stringify(r3));
const r4 = await page.evaluate(() => window.__call({ module: 'kz.gov.pki.knca.commonUtils', method: 'nope', args: [] }));
console.log('no such method', JSON.stringify(r4));
const probe = await page.evaluate(async () => {
  const r = await fetch('https://127.0.0.1:13579/', { mode: 'no-cors' });
  return r.status;
});
console.log('probe', probe);
const inst = await page.evaluate(() => {
  const w = new WebSocket('wss://127.0.0.1:13579');
  const res = { instanceofWS: w instanceof WebSocket, tag: Object.prototype.toString.call(w), rs: w.readyState, CONNECTING: w.CONNECTING };
  w.close();
  return res;
});
console.log('virtual socket', JSON.stringify(inst));
const lna = await page.evaluate(async () => (await navigator.permissions.query({ name: 'loopback-network' })).state);
console.log('loopback-network permission', lna);
await context.close();
server.close();
