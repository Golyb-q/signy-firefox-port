// Extension settings and small persistent stores (chrome.storage.local).

export const DEFAULT_SETTINGS = {
  enabled: true,
  disabledOrigins: [], // origins where Signy must not emulate NCALayer
  extraOrigins: [], // user-approved non-.kz origins ("https://example.com")
  allowTestCa: false, // trust NCA RK TEST certificates (developers)
  extraTrustPem: [], // additional trusted CA certificates (PEM), e.g. a developer test CA
  tsaUrl: 'http://tsp.pki.gov.kz',
  rememberKeysDefault: false,
  uiLocale: 'auto', // 'auto' (from request), 'ru', 'kk'
};

export async function getSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

export async function updateSettings(patch) {
  const s = await getSettings();
  const next = { ...s, ...patch };
  await chrome.storage.local.set({ settings: next });
  return next;
}

export function originAllowed(settings, origin) {
  if (!settings.enabled) return false;
  if (settings.disabledOrigins.includes(origin)) return false;
  return true;
}

// ---------------------------------------------------------------- remembered keys

/** Keys are stored exactly as the user's encrypted PKCS#12 file; the password is never stored. */
export async function listKeys() {
  const { keys } = await chrome.storage.local.get('keys');
  return Array.isArray(keys) ? keys : [];
}

export async function saveKey(entry) {
  const keys = await listKeys();
  const i = keys.findIndex((k) => k.id === entry.id);
  if (i >= 0) keys[i] = { ...keys[i], ...entry };
  else keys.push(entry);
  await chrome.storage.local.set({ keys });
}

export async function removeKey(id) {
  const keys = (await listKeys()).filter((k) => k.id !== id);
  await chrome.storage.local.set({ keys });
}

// ---------------------------------------------------------------- site history

export async function getSiteHistory() {
  const { sites } = await chrome.storage.local.get('sites');
  return sites && typeof sites === 'object' ? sites : {};
}

export async function recordSiteUse(origin) {
  const sites = await getSiteHistory();
  const s = sites[origin] || { count: 0, first: Date.now() };
  s.count++;
  s.last = Date.now();
  sites[origin] = s;
  await chrome.storage.local.set({ sites });
}

export async function forgetSite(origin) {
  const sites = await getSiteHistory();
  delete sites[origin];
  await chrome.storage.local.set({ sites });
}
