// E2E helpers: static server, browser launch with the unpacked extension.
import { createServer } from 'node:http';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import { homedir } from 'node:os';

export const ROOT = new URL('../../', import.meta.url).pathname;
export const EXT = join(ROOT, 'extension');

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.pem': 'text/plain', '.p12': 'application/x-pkcs12', '.png': 'image/png' };

export function startServer(routes = {}) {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    for (const [k, fn] of Object.entries(routes)) if (url.pathname === k || url.pathname.startsWith(k.replace(/\/$/, '') + '/')) return fn(req, res);
    let p = url.pathname === '/' ? '/index.html' : url.pathname;
    const file = join(ROOT, 'test/harness', decodeURIComponent(p));
    if (!file.startsWith(join(ROOT, 'test/harness')) || !existsSync(file)) {
      res.writeHead(404);
      return res.end('not found');
    }
    res.writeHead(200, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(readFileSync(file));
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port })));
}

export async function loadPlaywright() {
  const candidates = [];
  const npx = join(homedir(), '.npm/_npx');
  if (existsSync(npx)) {
    for (const d of readdirSync(npx)) {
      const p = join(npx, d, 'node_modules/playwright/index.mjs');
      if (existsSync(p)) candidates.push(p);
    }
  }
  const envPath = process.env.PLAYWRIGHT_MODULE;
  if (envPath) candidates.unshift(envPath);
  for (const c of candidates) {
    try {
      return await import(c);
    } catch {
      /* try next */
    }
  }
  return import('playwright');
}

export function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const cache = join(homedir(), 'Library/Caches/ms-playwright');
  const dirs = existsSync(cache) ? readdirSync(cache).filter((d) => /^chromium-\d+$/.test(d)).sort((a, b) => +b.split('-')[1] - +a.split('-')[1]) : [];
  for (const d of dirs) {
    for (const rel of [
      'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
      'chrome-mac/Chromium.app/Contents/MacOS/Chromium',
      'chrome-linux/chrome',
    ]) {
      const p = join(cache, d, rel);
      if (existsSync(p)) return p;
    }
  }
  return undefined;
}

export async function launch({ headless = true } = {}) {
  const pw = await loadPlaywright();
  const chromium = pw.chromium || (pw.default && pw.default.chromium);
  const userDataDir = join(process.env.TMPDIR || '/tmp', 'signy-e2e-' + Date.now());
  const context = await chromium.launchPersistentContext(userDataDir, {
    headless,
    executablePath: findChrome(),
    ignoreDefaultArgs: ['--disable-extensions', '--disable-component-extensions-with-background-pages'],
    args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, '--no-first-run', '--no-default-browser-check'],
    viewport: { width: 1100, height: 900 },
  });
  let sw = context.serviceWorkers()[0];
  if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 15000 });
  const extensionId = new URL(sw.url()).host;
  return { context, sw, extensionId };
}

export function file(...p) {
  return join(ROOT, ...p);
}

export { readFileSync, statSync };
