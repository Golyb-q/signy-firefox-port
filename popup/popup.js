import { getSettings, updateSettings, listKeys, removeKey } from '../lib/settings.js';
import { el, fmtDate } from '../ui/format.js';

const $ = (id) => document.getElementById(id);

function isDefaultSite(url) {
  return /^https?:\/\/([^/]*\.)?kz(:\d+)?\//i.test(url) || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(url);
}

async function render() {
  const s = await getSettings();
  $('version').textContent = 'v' + chrome.runtime.getManifest().version;
  $('globalToggle').checked = s.enabled;
  $('globalState').textContent = s.enabled ? 'Включена' : 'Выключена — сайты не увидят NCALayer';
  $('globalState').className = 'state ' + (s.enabled ? 'on' : 'off');

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab && tab.url ? tab.url : '';
  if (/^https?:/.test(url)) {
    const origin = new URL(url).origin;
    $('siteCard').hidden = false;
    $('siteOrigin').textContent = origin;
    const covered = isDefaultSite(url) || s.extraOrigins.includes(origin);
    const disabled = s.disabledOrigins.includes(origin);
    $('siteEnable').hidden = covered;
    $('siteDisable').hidden = !covered || disabled;
    $('siteReenable').hidden = !disabled;
    $('siteState').textContent = !covered ? 'Signy не работает на этом сайте (не .kz). Разрешите, если сайт использует NCALayer.'
      : disabled ? 'Отключено для этого сайта' : 'Запросы к NCALayer обрабатывает Signy';
    $('siteState').className = 'state small ' + (covered && !disabled ? 'on' : 'off');
    $('siteEnable').onclick = async () => {
      const ok = await chrome.permissions.request({ origins: [origin + '/*'] });
      if (!ok) return;
      await updateSettings({ extraOrigins: [...new Set([...s.extraOrigins, origin])] });
      chrome.tabs.reload(tab.id);
      render();
    };
    $('siteDisable').onclick = async () => {
      await updateSettings({ disabledOrigins: [...new Set([...s.disabledOrigins, origin])] });
      chrome.tabs.reload(tab.id);
      render();
    };
    $('siteReenable').onclick = async () => {
      await updateSettings({ disabledOrigins: s.disabledOrigins.filter((o) => o !== origin) });
      chrome.tabs.reload(tab.id);
      render();
    };
  }

  const keys = await listKeys();
  const ul = $('keys');
  ul.textContent = '';
  $('noKeys').hidden = keys.length > 0;
  for (const k of keys) {
    const sum = (k.summary && k.summary[0]) || {};
    ul.append(el('li', {},
      el('div', { class: 'k' },
        el('div', { class: 'ellipsis', text: sum.cn || k.name }),
        el('div', { class: 'sub ellipsis', text: [k.name, sum.notAfter ? 'до ' + fmtDate(new Date(sum.notAfter)) : ''].filter(Boolean).join(' · ') })),
      el('button', { class: 'icon-btn', type: 'button', title: 'Удалить ключ из Signy', text: '✕', onclick: async () => { await removeKey(k.id); render(); } })));
  }
}

$('globalToggle').addEventListener('change', async (e) => {
  await updateSettings({ enabled: e.target.checked });
  render();
});
$('openOptions').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});
$('openTest').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: chrome.runtime.getURL('web/ncalayer.html') });
});
render();
