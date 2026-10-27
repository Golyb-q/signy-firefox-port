import { getSettings, updateSettings, listKeys, removeKey, getSiteHistory, forgetSite } from '../lib/settings.js';
import { el, fmtDate } from '../ui/format.js';
import { parsePemList } from '../lib/ncalayer/certcheck.js';

const $ = (id) => document.getElementById(id);

function listInto(ul, items, render) {
  ul.textContent = '';
  if (!items.length) ul.append(el('li', { class: 'empty', text: '—' }));
  for (const it of items) ul.append(render(it));
}

async function render() {
  const s = await getSettings();
  $('enabled').checked = s.enabled;
  $('rememberKeysDefault').checked = s.rememberKeysDefault;
  $('uiLocale').value = s.uiLocale;
  $('tsaUrl').value = s.tsaUrl;
  $('allowTestCa').checked = s.allowTestCa;
  $('extraTrustPem').value = (s.extraTrustPem || []).join('\n');
  listInto($('extraOrigins'), s.extraOrigins, (o) => el('li', {}, el('span', { text: o }), el('button', { class: 'btn secondary', type: 'button', text: 'Убрать', onclick: async () => {
    await updateSettings({ extraOrigins: s.extraOrigins.filter((x) => x !== o) });
    await chrome.permissions.remove({ origins: [o + '/*'] }).catch(() => {});
    render();
  } })));
  listInto($('disabledOrigins'), s.disabledOrigins, (o) => el('li', {}, el('span', { text: o }), el('button', { class: 'btn secondary', type: 'button', text: 'Включить', onclick: async () => {
    await updateSettings({ disabledOrigins: s.disabledOrigins.filter((x) => x !== o) });
    render();
  } })));
  const sites = await getSiteHistory();
  listInto($('sites'), Object.entries(sites).sort((a, b) => b[1].last - a[1].last), ([o, v]) => el('li', {},
    el('span', { text: `${o} · ${v.count} раз, последний ${fmtDate(new Date(v.last))}` }),
    el('button', { class: 'btn secondary', type: 'button', text: 'Забыть', onclick: async () => { await forgetSite(o); render(); } })));
  const keys = await listKeys();
  listInto($('keys'), keys, (k) => {
    const sum = (k.summary && k.summary[0]) || {};
    return el('li', {}, el('span', { text: `${sum.cn || k.name} · ${k.name}${sum.notAfter ? ' · до ' + fmtDate(new Date(sum.notAfter)) : ''}` }),
      el('button', { class: 'btn secondary', type: 'button', text: 'Удалить', onclick: async () => { await removeKey(k.id); render(); } }));
  });
}

$('save').addEventListener('click', async () => {
  const pemText = $('extraTrustPem').value.trim();
  const pems = pemText ? pemText.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [] : [];
  const valid = pems.filter((p) => parsePemList([p]).length === 1);
  await updateSettings({
    enabled: $('enabled').checked,
    rememberKeysDefault: $('rememberKeysDefault').checked,
    uiLocale: $('uiLocale').value,
    tsaUrl: $('tsaUrl').value.trim() || 'http://tsp.pki.gov.kz',
    allowTestCa: $('allowTestCa').checked,
    extraTrustPem: valid,
  });
  $('saved').hidden = false;
  setTimeout(() => ($('saved').hidden = true), 1500);
  render();
});

$('deleteAllKeys').addEventListener('click', async () => {
  if (!confirm('Удалить все сохранённые в Signy ключи? Файлы ключей на диске не затрагиваются.')) return;
  await chrome.storage.local.set({ keys: [] });
  render();
});

render();
