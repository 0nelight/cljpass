// cljpass - UI in the style of KeePass 2.x (Windows)
// Security: user data only via textContent, never innerHTML.
'use strict';

// ============================================================== Helpers

const $ = (s, r = document) => r.querySelector(s);

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'html') el.innerHTML = v; // only for static icons
    else if (k in el && typeof v !== 'string') el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

// Form label with a colon
const lbl = (text) => h('label', {}, text + ':');

const ICONS = {
  add: '<path d="M8 3v10M3 8h10"/>',
  edit: '<path d="M10.5 2.5l3 3L6 13H3v-3z"/>',
  del: '<path d="M3 4h10M6 4V2.5h4V4M4.5 4l.7 9.5h5.6l.7-9.5"/>',
  dup: '<rect x="5" y="5" width="8.5" height="8.5"/><path d="M3 11V2.5h8.5"/>',
  user: '<circle cx="8" cy="5.5" r="2.7"/><path d="M2.8 14c.6-2.9 2.7-4.3 5.2-4.3s4.6 1.4 5.2 4.3"/>',
  key: '<circle cx="5" cy="10.5" r="2.8"/><path d="M7 8.5L13.5 2M11 4.5l1.8 1.8M9.6 5.9l1.3 1.3"/>',
  url: '<path d="M6.8 9.2a3 3 0 004.2 0l2-2a3 3 0 00-4.2-4.2l-.9.9M9.2 6.8a3 3 0 00-4.2 0l-2 2a3 3 0 004.2 4.2l.9-.9"/>',
  share: '<circle cx="4" cy="8" r="1.8"/><circle cx="12" cy="3.8" r="1.8"/><circle cx="12" cy="12.2" r="1.8"/><path d="M5.6 7.1l4.8-2.4M5.6 8.9l4.8 2.4"/>',
  sync: '<path d="M13 5.5A5.3 5.3 0 003.5 5M3 10.5A5.3 5.3 0 0012.5 11M13 2.5v3h-3M3 13.5v-3h3"/>',
  lock: '<rect x="3.5" y="7" width="9" height="6.5"/><path d="M5.5 7V5a2.5 2.5 0 015 0v2"/>',
  gen: '<path d="M2.5 13.5l7-7M9.5 2.5l.7 1.6 1.6.7-1.6.7-.7 1.6-.7-1.6-1.6-.7 1.6-.7zM12.5 8.5l.5 1 1 .5-1 .5-.5 1-.5-1-1-.5 1-.5z"/>',
  folder: '<path d="M1.8 4.2h4.4l1.3 1.4h6.7v7.2H1.8z"/>',
  folderOpen: '<path d="M1.8 12.8V4.2h4.4l1.3 1.4h5.3v1.6M1.8 12.8l1.7-5.2h11l-1.7 5.2z"/>',
  vault: '<rect x="2" y="2.5" width="12" height="11" rx="1"/><circle cx="8" cy="8" r="2.3"/><path d="M8 5.7V4.5M8 11.5v-1.2M10.3 8h1.2M4.5 8h1.2"/>',
  shared: '<circle cx="5.5" cy="5.5" r="2.2"/><circle cx="11" cy="6.2" r="1.8"/><path d="M1.8 13c.5-2.5 2-3.7 3.7-3.7s3.2 1.2 3.7 3.7M9.2 9.6c.5-.2 1.1-.3 1.8-.3 1.6 0 2.8 1 3.2 3.2"/>',
  entry: '<rect x="3" y="2" width="10" height="12" rx="1"/><path d="M5.5 5.5h5M5.5 8h5M5.5 10.5h3"/>',
  warn: '<path d="M8 2l6.3 11H1.7z"/><path d="M8 6.5v3M8 11.3v.2"/>',
  eye: '<path d="M1.5 8S4 3.5 8 3.5 14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8z"/><circle cx="8" cy="8" r="2"/>',
  readonly: '<rect x="4" y="7.5" width="8" height="6"/><path d="M6 7.5V6a2 2 0 014 0v1.5"/>',
  group: '<circle cx="6" cy="6" r="2.3"/><circle cx="11.3" cy="6.6" r="1.8"/><path d="M1.8 13.2c.5-2.6 2.1-3.8 4.2-3.8s3.7 1.2 4.2 3.8M10.3 9.6c2 0 3.3 1.1 3.8 3.4"/>',
  x: '<path d="M4 4l8 8M12 4l-8 8"/>',
  history: '<circle cx="8" cy="8" r="5.8"/><path d="M8 4.8V8l2.2 1.5"/>',
  conflict: '<path d="M2.5 4.5h7M7.5 2.5l2 2-2 2M13.5 11.5h-7M8.5 9.5l-2 2 2 2"/>',
  import: '<path d="M8 2v8M5 7l3 3 3-3M2.5 11v2.5h11V11"/>',
  export: '<path d="M8 10V2M5 5l3-3 3 3M2.5 11v2.5h11V11"/>',
  // Own drawings for the KeePass standard icons (see KP_ICONS)
  world: '<circle cx="8" cy="8" r="5.8"/><path d="M2.2 8h11.6M8 2.2c-2 1.8-2 9.8 0 11.6M8 2.2c2 1.8 2 9.8 0 11.6"/>',
  server: '<rect x="3" y="2.5" width="10" height="4.5" rx=".8"/><rect x="3" y="9" width="10" height="4.5" rx=".8"/><path d="M5 4.75h.1M5 11.25h.1"/>',
  mail: '<rect x="2" y="3.5" width="12" height="9" rx="1"/><path d="M2.5 4.5L8 9l5.5-4.5"/>',
  monitor: '<rect x="2" y="2.5" width="12" height="8.5" rx="1"/><path d="M6 13.5h4M8 11v2.5"/>',
  console: '<rect x="2" y="2.5" width="12" height="11" rx="1"/><path d="M4.5 6l2 2-2 2M8 10.5h3.5"/>',
  printer: '<path d="M4.5 6V2.5h7V6M4.5 11H2.5V6h11v5h-2"/><rect x="4.5" y="9" width="7" height="4.5"/>',
  disk: '<rect x="2.5" y="2.5" width="11" height="11" rx="1"/><path d="M5 2.5v4h6v-4M5 13.5v-4h6v4"/>',
  drive: '<rect x="2" y="5" width="12" height="6" rx="1"/><path d="M11 8h.1M4.5 8h3"/>',
  cd: '<circle cx="8" cy="8" r="5.8"/><circle cx="8" cy="8" r="1.5"/>',
  camera: '<path d="M2 5h3l1-1.5h4L11 5h3v8H2z"/><circle cx="8" cy="9" r="2.3"/>',
  energy: '<path d="M9 1.8L4 9h4l-1 5.2L12 7H8z"/>',
  star: '<path d="M8 2l1.8 3.8 4.1.5-3 2.8.8 4.1L8 11.2 4.3 13.2l.8-4.1-3-2.8 4.1-.5z"/>',
  home: '<path d="M2.5 7.5L8 3l5.5 4.5M4 6.5v7h8v-7M6.8 13.5v-3.5h2.4v3.5"/>',
  money: '<circle cx="8" cy="8" r="5.8"/><path d="M10 5.8c-.5-.6-1.2-.9-2-.9-1.1 0-2 .7-2 1.6 0 2.2 4 1.1 4 3.3 0 .9-.9 1.6-2 1.6-.8 0-1.6-.4-2-1M8 3.6v1.3M8 11.4v1.3"/>',
  cert: '<rect x="2" y="2.5" width="12" height="8" rx="1"/><path d="M4.5 5.5h7M4.5 7.5h4"/><circle cx="11" cy="11" r="1.8"/><path d="M10 12.5l-.5 2 1.5-.8 1.5.8-.5-2"/>',
  book: '<path d="M3 3h4.2c.5 0 .8.3.8.8V13c0-.5-.3-.8-.8-.8H3zM13 3H8.8c-.5 0-.8.3-.8.8V13c0-.5.3-.8.8-.8H13z"/>',
  list: '<path d="M6 4.5h7.5M6 8h7.5M6 11.5h7.5M2.8 4.5h.1M2.8 8h.1M2.8 11.5h.1"/>',
  tool: '<path d="M10.3 2.3a3 3 0 00-3.6 4L2.5 10.5a1.3 1.3 0 001.9 1.9l4.2-4.2a3 3 0 004-3.6L10.8 6.4 9.5 6.5l.1-1.3z"/>',
  gear: '<circle cx="8" cy="8" r="2.2"/><path d="M8 1.8v2M8 12.2v2M1.8 8h2M12.2 8h2M3.6 3.6l1.4 1.4M11 11l1.4 1.4M3.6 12.4L5 11M11 5l1.4-1.4"/>',
  box: '<path d="M2.5 5L8 2.5 13.5 5v6.5L8 14l-5.5-2.5zM2.5 5L8 7.5 13.5 5M8 7.5V14"/>',
  info: '<circle cx="8" cy="8" r="5.8"/><path d="M8 7.2v4M8 4.9v.1"/>',
  lockOpen: '<rect x="3.5" y="7" width="9" height="6.5"/><path d="M5.5 7V5a2.5 2.5 0 014.9-.7"/>',
  check: '<path d="M3 8.5l3 3 7-7"/>',
  clipboard: '<rect x="3.5" y="3" width="9" height="11" rx="1"/><path d="M6 3V2h4v1M5.5 7h5M5.5 9.5h5"/>',
  phone: '<rect x="4.5" y="1.5" width="7" height="13" rx="1.2"/><path d="M7 12.5h2"/>',
  apple: '<path d="M8 5c-1-1-4-1-4.5 2.2S5 13 6.5 13c.7 0 .9-.4 1.5-.4s.8.4 1.5.4c1.5 0 3-3.8 2.5-5.8S9 4 8 5zM8 5c0-1.3.7-2.3 2-2.5"/>',
  tux: '<path d="M8 2c-1.7 0-2.5 1.5-2.5 3.5 0 1-.8 2-1.5 3.5S3.5 13.5 5 13.5h6c1.5 0 1.7-2 1-3.5S10.5 6.5 10.5 5.5C10.5 3.5 9.7 2 8 2z"/><path d="M6.8 5h.1M9.2 5h.1"/>',
  feather: '<path d="M13 3C8 3 4.5 6.5 4.5 11.5M13 3c0 5-3.5 8.5-8.5 8.5M2.5 13.5l2-2M7 9h3"/>',
  wiki: '<path d="M2 4l2.5 8L7 6h2l2.5 6L14 4"/>',
  archive: '<rect x="2" y="3" width="12" height="3.5"/><path d="M3 6.5v7h10v-7M6.5 9h3"/>',
  bank: '<path d="M2 6L8 2.5 14 6M3.5 6.5v5.5M6.5 6.5v5.5M9.5 6.5v5.5M12.5 6.5v5.5M2 13.5h12"/>',
  identity: '<rect x="2" y="3" width="12" height="10" rx="1"/><circle cx="5.8" cy="7.2" r="1.5"/><path d="M3.8 11c.4-1.2 1.1-1.8 2-1.8s1.6.6 2 1.8M9.5 6.5h3M9.5 9h3"/>',
  thumb: '<rect x="2" y="3" width="12" height="10" rx="1"/><path d="M2.5 11.5l3.5-3.5 2.5 2.5 2-2 3 3"/><circle cx="10.5" cy="6" r="1"/>',
};

// KeePass standard icons (IconID 0-68) -> own drawings
const KP_ICONS = [
  'key', 'world', 'warn', 'server', 'folder', 'user', 'gear', 'entry', 'world', 'identity',
  'entry', 'camera', 'user', 'key', 'energy', 'printer', 'star', 'cd', 'monitor', 'mail',
  'gear', 'clipboard', 'entry', 'monitor', 'energy', 'mail', 'disk', 'drive', 'entry', 'console',
  'console', 'printer', 'box', 'console', 'gear', 'monitor', 'archive', 'bank', 'drive', 'history',
  'mail', 'entry', 'drive', 'del', 'entry', 'warn', 'info', 'box', 'folder', 'folderOpen',
  'box', 'lockOpen', 'lock', 'check', 'edit', 'thumb', 'book', 'list', 'user', 'tool',
  'home', 'star', 'tux', 'feather', 'apple', 'wiki', 'money', 'cert', 'phone',
];

const icon = (n) => '<svg class="i" viewBox="0 0 16 16" aria-hidden="true">' + (ICONS[n] || '') + '</svg>';
const iconEl = (n) => h('span', { class: 'ic', html: icon(n) });

// Icon of an entry/folder from KeePass: custom image (data: URL) or standard icon
function kpIconEl(ic, fallback = 'key') {
  if (ic && ic.custom && /^data:image\/(png|jpeg|gif|x-icon|bmp|webp);base64,/.test(ic.custom['data-url'] || '')) {
    return h('span', { class: 'ic' }, h('img', { class: 'kpimg', src: ic.custom['data-url'], alt: '', title: ic.custom.name || '' }));
  }
  return iconEl(ic ? (KP_ICONS[ic.id] || fallback) : fallback);
}
const entryIconEl = (e) => (e && e['kdbx-database'] ? iconEl('vault') : kpIconEl(e && e.icon));

// ============================================================== Translations
// Texts come from the server (op "i18n", catalogs resources/i18n/ui.<lang>.edn).
// Keys are always written literally, t('ui/<key>') - a test checks that they exist.

const i18n = { lang: '', auto: true, languages: ['en', 'de'], messages: {} };

function fill(s, params) {
  if (!params) return s;
  return s.replace(/\{([A-Za-z0-9_-]+)\}/g, (m, p) => (Object.prototype.hasOwnProperty.call(params, p) ? String(params[p]) : m));
}

// Text for a key in the current language; unknown keys show the key itself
function t(key, params) {
  const s = i18n.messages[key];
  return fill(s == null ? key : s, params);
}

// Counted text: <key>.one for n = 1, else <key>.other; {n} is filled in
function tn(key, n, params) {
  return t(key + (n === 1 ? '.one' : '.other'), { ...params, n });
}

// Locale for dates and times
const dateLocale = () => (i18n.lang === 'de' ? 'de-AT' : 'en-GB');

async function loadCatalog() {
  const r = await api('i18n');
  i18n.lang = r.lang;
  i18n.auto = !!r.auto;
  i18n.languages = r.languages || i18n.languages;
  i18n.messages = r.messages || {};
  document.documentElement.lang = r.lang;
  document.title = t('ui/app-title');
  $('#tree').setAttribute('aria-label', t('ui/folders'));
  $('#list').setAttribute('aria-label', t('ui/entries'));
  $('#empty').textContent = t('ui/no-entries');
}

async function setLang(lang) {
  try {
    await api('set-lang', { lang });
    i18n.lang = '';
    await loadCatalog();
    if (!$('#app').hidden) render(); else boot();
  } catch (e) { fail(e); }
}

async function api(op, params = {}) {
  const headers = { 'Content-Type': 'application/json', 'X-CljPass': '1' };
  if (i18n.lang) headers['X-CljPass-Lang'] = i18n.lang;
  const r = await fetch('/api/' + op, {
    method: 'POST',
    headers,
    body: JSON.stringify(params),
    credentials: 'same-origin',
  });
  let data;
  try { data = await r.json(); } catch { data = { error: t('ui/no-response', { status: r.status }) }; }
  if (!r.ok || data.error) {
    const e = new Error(data.error || t('ui/error-status', { status: r.status }));
    e.type = data.type; e.status = r.status;
    if (r.status === 423) showLocked();
    throw e;
  }
  return data.result;
}

function toast(msg, isError) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast' + (isError ? ' error' : '');
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), isError ? 6000 : 3000);
}

const fail = (e) => { if (e && e.status !== 423) toast(e.message || String(e), true); };

const fmtDate = (s) => {
  if (!s) return '';
  const d = new Date(s);
  return isNaN(d) ? s : d.toLocaleString(dateLocale(), { dateStyle: 'short', timeStyle: 'short' });
};

const PERMS = () => ({ read: t('ui/perm-read'), update: t('ui/perm-update'), owner: t('ui/perm-owner') });
const PERM_RANK = { read: 1, update: 2, owner: 3 };
const canEdit = (e) => e && PERM_RANK[e.permission] >= 2;
const isOwner = (e) => e && e.permission === 'owner';

function colorFor(name) {
  let x = 0;
  for (const ch of name) x = (x * 31 + ch.charCodeAt(0)) >>> 0;
  return 'hsl(' + (x % 360) + ' 45% 42%)';
}

function avatar(p) {
  const initials = (p.display || p.name || '?').split(/[\s._-]+/).map((s) => s[0]).join('').slice(0, 2).toUpperCase();
  const a = h('span', { class: 'avatar' + (p.kind === 'group' ? ' group' : '') });
  a.style.background = colorFor(p.principal || p.name || '');
  if (p.kind === 'group') a.innerHTML = icon('group'); else a.textContent = initials;
  return a;
}

// ============================================================== State

const state = {
  me: null, org: '', entries: [], folderIcons: {}, folder: '', search: '',
  sort: { key: 'title', dir: 1 }, selected: null, pending: 0, conflicts: 0,
  lastSync: null, online: true,
  // 'server' or 'standalone' (local KeePass file without a server)
  mode: 'server', file: '', link: null, defaults: {}, standaloneAllowed: true,
};
const isLocal = () => state.mode === 'standalone';

// ============================================================== Start screens

function screen(card) {
  const s = $('#screen');
  s.replaceChildren(card);
  s.hidden = false;
  $('#app').hidden = true;
}

// File path with "Browse..." (Windows dialog; otherwise type the path)
function filePicker(value, save) {
  const input = h('input', { type: 'text', value: value || '', spellcheck: false, 'aria-label': t('ui/file') });
  const btn = h('button', { class: 'btn', type: 'button', hidden: true, onclick: async () => {
    try {
      const r = await api('pick-file', { save: typeof save === 'function' ? save() : !!save, file: input.value });
      if (r.file) input.value = r.file;
    } catch (e) { fail(e); }
  } }, t('ui/browse'));
  api('pick-file', { probe: true }).then((r) => { btn.hidden = !r.supported; }).catch(() => {});
  return { input, el: h('div', { class: 'row' }, input, btn) };
}

// Form for the local file: create or open
function localForm({ file, create, onDone, switchable }) {
  let isNew = !!create;
  const picker = filePicker(file, () => isNew);
  const pw = h('input', { type: 'password', autocomplete: 'off' });
  const pw2 = h('input', { type: 'password', autocomplete: 'new-password' });
  const kf = h('input', { type: 'file' });
  const err = h('div', { class: 'err' });
  const go = h('button', { class: 'btn primary', type: 'submit' });
  const repeatRow = [h('label', {}, t('ui/master-password-repeat')), pw2];
  const radio = (v, label) => h('label', { class: 'opt' }, h('input', { type: 'radio', name: 'lf-mode', checked: isNew === v,
    onchange: () => { isNew = v; update(); } }), label);
  const update = () => {
    go.textContent = isNew ? t('ui/file-create') : t('ui/open');
    repeatRow.forEach((x) => { x.hidden = !isNew; });
    pw.autocomplete = isNew ? 'new-password' : 'off';
  };
  const form = h('form', {
    onsubmit: async (ev) => {
      ev.preventDefault();
      err.textContent = '';
      if (isNew && pw.value !== pw2.value) { err.textContent = t('ui/password-mismatch'); return; }
      if (!pw.value && !kf.files[0]) { err.textContent = t('ui/master-password-or-keyfile-required'); return; }
      go.disabled = true;
      try {
        await api('open-file', { file: picker.input.value.trim(), password: pw.value, create: isNew,
          keyfile: kf.files[0] ? await readBase64(kf.files[0]) : '' });
        pw.value = pw2.value = '';
        onDone();
      } catch (e) { err.textContent = e.message; go.disabled = false; }
    },
  },
  switchable ? h('div', { class: 'opts' }, radio(true, t('ui/new-file-create')), radio(false, t('ui/existing-file-open'))) : null,
  h('div', { class: 'form' },
    h('label', {}, t('ui/keepass-file-kdbx')), picker.el,
    h('label', {}, t('ui/master-password')), pw,
    ...repeatRow,
    h('label', {}, t('ui/keyfile-optional')), kf),
  err,
  h('div', { class: 'actions' }, go));
  update();
  return { form, focus: () => (picker.input.value ? pw : picker.input).focus() };
}

function showEnroll(st) {
  const d = st.defaults || {};
  const allowLocal = st['standalone-allowed'] !== false;
  let choice = d.server || !allowLocal ? 'server' : 'local';

  // --- Server
  const server = h('input', { type: 'url', value: d.server || '', placeholder: t('ui/server-placeholder') });
  const hash = h('input', { type: 'text', value: d['org-hash'] || '', placeholder: t('ui/org-hash-placeholder') });
  const user = h('input', { type: 'text', value: st.user || '' });
  const err = h('div', { class: 'err' });
  const go = h('button', { class: 'btn primary', type: 'submit' }, t('ui/enroll-button'));
  const serverForm = h('form', {
    onsubmit: async (ev) => {
      ev.preventDefault();
      go.disabled = true; err.textContent = '';
      try {
        await api('enroll', { server: server.value.trim(), 'org-hash': hash.value.trim(), user: user.value.trim() });
        boot();
      } catch (e) { err.textContent = e.message; go.disabled = false; }
    },
  },
  h('p', {}, t('ui/enroll-intro')),
  h('div', { class: 'form' },
    h('label', {}, t('ui/server')), server,
    h('label', {}, t('ui/enroll-org-hash')), hash,
    h('label', {}, t('ui/enroll-user')), user),
  err,
  h('div', { class: 'actions' }, go));

  // --- Local file
  const lf = localForm({ file: st.file, create: true, switchable: true, onDone: boot });
  const localBox = h('div', {},
    h('p', {}, t('ui/enroll-local-intro')),
    lf.form);

  const body = h('div');
  const tab = (k, title, sub) => h('button', { type: 'button', class: 'choice' + (choice === k ? ' on' : ''),
    onclick: () => { choice = k; render(); } }, h('b', {}, title), h('span', {}, sub));
  const render = () => {
    body.replaceChildren(
      allowLocal ? h('div', { class: 'choices' },
        tab('local', t('ui/choice-local'), t('ui/choice-local-sub')),
        tab('server', t('ui/choice-server'), t('ui/choice-server-sub'))) : null,
      choice === 'local' ? localBox : serverForm);
    setTimeout(() => (choice === 'local' ? lf.focus() : (server.value ? user : server).focus()), 0);
  };
  screen(h('div', { class: 'card' }, h('h1', { html: icon('vault') }, h('span', {}, t('ui/enroll-title'))), body));
  render();
}

function showOpenFile(st) {
  state.mode = 'standalone';
  let create = false;
  const card = h('div', { class: 'card' });
  const render = () => {
    const lf = localForm({ file: st.file || state.file, create, onDone: boot });
    card.replaceChildren(
      h('h1', { html: icon('lock') }, h('span', {}, create ? t('ui/new-file-create') : t('ui/database-open'))),
      h('p', {}, create ? t('ui/new-file-intro') : t('ui/file-locked-intro')),
      lf.form,
      h('p', { class: 'hint' }, h('a', { href: '#', onclick: (ev) => { ev.preventDefault(); create = !create; render(); } },
        create ? t('ui/existing-file-open') : t('ui/other-or-new-file'))));
    setTimeout(lf.focus, 0);
  };
  render();
  screen(card);
  closeAllDialogs();
}

function showPending(st) {
  screen(h('div', { class: 'card' },
    h('h1', { html: icon('user') }, h('span', {}, t('ui/pending-title'))),
    h('p', {}, t('ui/pending-intro')),
    h('div', { class: 'fp' }, st.fingerprint || ''),
    h('p', {}, h('span', { class: 'spinner' }), t('ui/pending-auto-refresh'))));
  clearTimeout(showPending.t);
  showPending.t = setTimeout(boot, 5000);
}

function showLocked() {
  if (isLocal()) return showOpenFile({ file: state.file });
  const btn = h('button', { class: 'btn primary', onclick: unlock }, t('ui/unlock'));
  screen(h('div', { class: 'card' },
    h('h1', { html: icon('lock') }, h('span', {}, t('ui/locked-title'))),
    h('p', {}, t('ui/locked-intro')),
    h('div', { class: 'actions' }, btn)));
  closeAllDialogs();
  btn.focus();
}

async function unlock() {
  try { await api('unlock'); boot(); } catch (e) { fail(e); }
}

async function lock() {
  try { await api('lock'); } catch (e) { /* ignore */ }
  state.entries = [];
  showLocked();
}

async function boot() {
  let st;
  try {
    if (!i18n.lang) await loadCatalog();
    st = await api('status');
  } catch (e) {
    if (e.status === 423) return;
    screen(h('div', { class: 'card' }, h('h1', {}, t('ui/error')), h('p', {}, e.message),
      h('div', { class: 'actions' }, h('button', { class: 'btn', onclick: boot }, t('ui/retry')))));
    return;
  }
  state.mode = st.mode || 'server';
  if (st.file) state.file = st.file;
  if (st.state === 'not-enrolled') return showEnroll(st);
  if (st.state === 'locked') return isLocal() ? showOpenFile(st) : showLocked();
  if (st.state === 'pending') return showPending(st);
  $('#screen').hidden = true;
  $('#app').hidden = false;
  state.me = st.user;
  state.defaults = st.defaults || {};
  state.standaloneAllowed = st['standalone-allowed'] !== false;
  noteLink(st.link);
  noteSync(st.sync);
  await refresh();
  $('#listwrap').focus();
}

// ============================================================== Data

async function refresh(keepSelection = true) {
  const r = await api('entries');
  state.entries = r.entries || [];
  state.folderIcons = Object.fromEntries((r['folder-icons'] || []).map((f) => [f.folder, f.icon]));
  state.org = r.org || t('ui/vault');
  state.mode = r.mode || state.mode;
  if (r.file) state.file = r.file;
  state.me = r.user;
  state.displayName = r['display-name'];
  state.pending = r.pending || 0;
  state.conflicts = r.conflicts || 0;
  if (!keepSelection || !state.entries.find((e) => e.id === state.selected)) state.selected = null;
  for (const err of r.errors || []) toast(t('ui/entry-unreadable', { error: err.error }), true);
  render();
}

async function doSync(quiet) {
  try {
    const r = await api('sync', quiet ? { background: true } : {});
    noteSync(r);
    await refresh();
    if (!quiet) toast(r.online ? t('ui/synced') : t('ui/server-unreachable-offline'));
  } catch (e) { if (!quiet) fail(e); }
}

// Requested server connection in local mode
function noteLink(link) {
  state.link = isLocal() ? link || null : null;
  renderBanner();
  if (state.link && state.link.state === 'ready') finishConnect();
}

async function finishConnect() {
  if (finishConnect.busy) return;
  finishConnect.busy = true;
  try {
    const r = await api('connect-finish');
    toast(t('ui/connected-summary', { created: r.created, updated: r.updated }) +
      (r.copied ? t('ui/connected-copied', { n: r.copied }) : '') +
      (r.deleted ? t('ui/connected-deleted', { n: r.deleted }) : ''));
    state.link = null;
    await boot();
  } catch (e) { fail(e); } finally { finishConnect.busy = false; }
}

function renderBanner() {
  const b = $('#banner');
  const l = state.link;
  if (!l || !isLocal()) { b.hidden = true; return; }
  const text = {
    pending: [t('ui/link-pending-before', { server: l.server || '' }),
      h('b', { class: 'mono' }, l.fingerprint || ''), t('ui/link-pending-after')],
    offline: [t('ui/link-offline', { server: l.server || '' })],
    ready: [h('span', { class: 'spinner' }), t('ui/link-ready')],
    error: [t('ui/link-error', { error: l.error || t('ui/error') })],
  }[l.state] || [];
  b.replaceChildren(h('span', { class: 'ic', html: icon('sync') }), h('span', { class: 'grow' }, ...text),
    l.state === 'ready' ? null : h('button', { class: 'btn', onclick: async () => {
      try { await api('connect-cancel'); state.link = null; renderBanner(); toast(t('ui/link-withdrawn')); } catch (e) { fail(e); }
    } }, t('ui/link-withdraw')));
  b.hidden = false;
}

function noteSync(r) {
  if (!r) return;
  if (r.standalone) { if (r.reloaded) toast(t('ui/file-reloaded')); return; }
  state.online = r.online !== false;
  state.lastSync = new Date();
  if (r.push && r.push.conflicts) toast(tn('ui/sync-conflicts', r.push.conflicts), true);
  if (r.push && r.push.rejected) toast(tn('ui/sync-rejected', r.push.rejected), true);
  for (const l of r.log || []) toast(l);
}

// ============================================================== Menu and toolbar

const sel = () => state.entries.find((e) => e.id === state.selected);

function actions() {
  const e = sel();
  const ctrl = (key) => t('ui/shortcut-ctrl', { key });
  // language choice: check mark on the active one
  const langIcon = (l) => ((l === 'auto' ? i18n.auto : !i18n.auto && i18n.lang === l) ? 'check' : '');
  return {
    add: { label: t('ui/entry-add-menu'), icon: 'add', sc: ctrl('I'), run: () => entryDialog(null) },
    edit: { label: canEdit(e) || !e ? t('ui/entry-edit-menu') : t('ui/entry-view-menu'), icon: 'edit', sc: t('ui/shortcut-enter'), on: !!e, run: () => entryDialog(e.id) },
    dup: { label: t('ui/entry-duplicate'), icon: 'dup', sc: ctrl('K'), on: !!e, run: duplicate },
    del: { label: t('ui/entry-delete'), icon: 'del', sc: t('ui/shortcut-delete'), on: isOwner(e), run: remove },
    user: { label: t('ui/copy-username'), icon: 'user', sc: ctrl('B'), on: !!e && !!e.username, run: () => copy('username', t('ui/field-username')) },
    pw: { label: t('ui/copy-password'), icon: 'key', sc: ctrl('C'), on: !!e, run: () => copy('password', t('ui/field-password')) },
    url: { label: t('ui/url-open'), icon: 'url', sc: ctrl('U'), on: !!e && !!e.url, run: openUrl },
    urlcopy: { label: t('ui/url-copy'), icon: 'url', on: !!e && !!e.url, run: () => copy('url', t('ui/field-url')) },
    share: { label: t('ui/share-menu'), icon: 'share', sc: ctrl('E'), on: !!e && !isLocal(), run: () => entryDialog(e.id, 'share') },
    history: { label: t('ui/history-menu'), icon: 'history', on: !!e, run: () => entryDialog(e.id, 'history') },
    sync: { label: isLocal() ? t('ui/reload') : t('ui/sync'), icon: 'sync', sc: 'F5', run: () => doSync(false) },
    lock: { label: t('ui/lock-workspace'), icon: 'lock', sc: ctrl('L'), run: lock },
    gen: { label: t('ui/generator-menu'), icon: 'gen', run: () => generatorDialog(null) },
    conflicts: { label: t('ui/conflicts-menu'), icon: 'conflict', on: !isLocal(), run: conflictsDialog },
    langAuto: { label: t('ui/lang-auto'), icon: langIcon('auto'), run: () => setLang('auto') },
    langEn: { label: t('ui/lang-en'), icon: langIcon('en'), run: () => setLang('en') },
    langDe: { label: t('ui/lang-de'), icon: langIcon('de'), run: () => setLang('de') },
    about: { label: t('ui/about-menu'), icon: 'vault', run: aboutDialog },
    kdbxImport: { label: t('ui/kdbx-import-menu'), icon: 'import', run: importDialog },
    kdbxExport: { label: isLocal() ? t('ui/save-copy-as-menu') : t('ui/kdbx-export-menu'), icon: 'export', run: exportDialog },
    openFile: { label: t('ui/open-other-file-menu'), icon: 'folderOpen', run: lock },
    syncFile: { label: t('ui/sync-file-menu'), icon: 'conflict', run: syncFileDialog },
    connect: { label: t('ui/connect-menu'), icon: 'share', on: !state.link, run: connectDialog },
    disconnect: { label: t('ui/disconnect-menu'), icon: 'export', on: state.standaloneAllowed, run: disconnectDialog },
  };
}

const menus = () => [
  [t('ui/menu-file'), isLocal()
    ? ['openFile', '-', 'syncFile', 'kdbxImport', 'kdbxExport', '-', 'connect', '-', 'sync', '-', 'lock']
    : ['kdbxImport', 'kdbxExport', '-', 'sync', '-', 'disconnect', '-', 'lock']],
  [t('ui/menu-entry'), ['add', 'edit', 'dup', 'del', '-', 'user', 'pw', 'url', 'urlcopy', '-', 'share', 'history']],
  [t('ui/menu-tools'), ['gen', '-', 'conflicts', '-', 'langAuto', 'langEn', 'langDe']],
  [t('ui/menu-help'), ['about']],
];

function buildMenu(keys, x, y) {
  const acts = actions();
  const m = $('#ctxmenu');
  m.replaceChildren(...keys.map((k) => {
    if (k === '-') return h('div', { class: 'sep' });
    const a = acts[k];
    const enabled = a.on !== false;
    return h('div', {
      class: 'item' + (enabled ? '' : ' disabled'), role: 'menuitem',
      onclick: () => { if (enabled) { closeMenu(); a.run(); } },
    }, h('span', { class: 'ic', html: icon(a.icon) }), a.label, h('span', { class: 'sc' }, a.sc || ''));
  }));
  m.hidden = false;
  const r = m.getBoundingClientRect();
  m.style.left = Math.min(x, innerWidth - r.width - 4) + 'px';
  m.style.top = Math.min(y, innerHeight - r.height - 4) + 'px';
}

function closeMenu() {
  $('#ctxmenu').hidden = true;
  document.querySelectorAll('.menubar .mi.open').forEach((x) => x.classList.remove('open'));
}

function renderMenubar() {
  const bar = $('#menubar');
  bar.replaceChildren(...menus().map(([title, keys]) => {
    const mi = h('div', { class: 'mi', role: 'menuitem' }, title);
    const open = () => {
      closeMenu();
      mi.classList.add('open');
      const r = mi.getBoundingClientRect();
      buildMenu(keys, r.left, r.bottom);
    };
    mi.addEventListener('mousedown', (ev) => { ev.stopPropagation(); mi.classList.contains('open') ? closeMenu() : open(); });
    mi.addEventListener('mouseenter', () => { if (bar.querySelector('.mi.open') && !mi.classList.contains('open')) open(); });
    return mi;
  }));
}

function renderToolbar() {
  const acts = actions();
  const tb = (k) => h('button', {
    class: 'tb', title: acts[k].label.replace('...', '') + (acts[k].sc ? ' (' + acts[k].sc + ')' : ''),
    disabled: acts[k].on === false, html: icon(acts[k].icon), onclick: () => acts[k].run(),
  });
  const sep = () => h('span', { class: 'tbsep' });
  const search = h('input', {
    type: 'search', id: 'search', placeholder: t('ui/search-placeholder'), value: state.search, 'aria-label': t('ui/search'),
    oninput: (ev) => { state.search = ev.target.value; renderList(); renderDetails(); renderStatus(); },
    onkeydown: (ev) => { if (ev.key === 'Enter' || ev.key === 'ArrowDown') { $('#listwrap').focus(); ev.preventDefault(); } },
  });
  $('#toolbar').replaceChildren(
    tb('sync'), tb('lock'), sep(),
    tb('add'), tb('edit'), tb('del'), sep(),
    tb('user'), tb('pw'), tb('url'), sep(),
    tb('share'), tb('gen'),
    h('div', { class: 'search' }, search));
}

// ============================================================== Folder tree

const SHARED_WITH_ME = '\u0000with-me';
const SHARED_BY_ME = '\u0000by-me';

function folderTree() {
  const root = { name: state.org, path: '', kids: new Map(), count: state.entries.length };
  for (const e of state.entries) {
    let node = root; let path = '';
    for (const part of (e.folder || '').split('/').map((s) => s.trim()).filter(Boolean)) {
      path = path ? path + '/' + part : part;
      if (!node.kids.has(part)) node.kids.set(part, { name: part, path, kids: new Map(), count: 0 });
      node = node.kids.get(part);
      node.count++;
    }
  }
  return root;
}

state.collapsed = new Set();

function renderTree() {
  const tree = $('#tree');
  const rows = [];
  const add = (node, depth) => {
    const hasKids = node.kids.size > 0;
    const open = !state.collapsed.has(node.path);
    const row = h('div', {
      class: 'node' + (state.folder === node.path ? ' sel' : ''),
      onclick: () => { state.folder = node.path; state.selected = null; render(); },
      oncontextmenu: (ev) => { ev.preventDefault(); state.folder = node.path; render(); buildMenu(['add'], ev.clientX, ev.clientY); },
    },
    h('span', { class: 'tw', onclick: (ev) => { ev.stopPropagation(); if (open) state.collapsed.add(node.path); else state.collapsed.delete(node.path); renderTree(); } },
      hasKids ? (open ? '▾' : '▸') : ''),
    folderIconEl(node.path, depth),
    node.name, h('span', { class: 'cnt' }, depth > 0 ? '(' + node.count + ')' : ''));
    row.style.paddingLeft = (4 + depth * 14) + 'px';
    rows.push(row);
    if (open) [...node.kids.values()].sort((a, b) => a.name.localeCompare(b.name, i18n.lang || 'en')).forEach((k) => add(k, depth + 1));
  };
  add(folderTree(), 0);
  for (const [path, name, ic] of isLocal() ? [] : [[SHARED_WITH_ME, t('ui/shared-with-me'), 'shared'], [SHARED_BY_ME, t('ui/shared-by-me'), 'share']]) {
    const n = state.entries.filter(matchFolder(path)).length;
    const row = h('div', { class: 'node virtual' + (state.folder === path ? ' sel' : ''), onclick: () => { state.folder = path; state.selected = null; render(); } },
      h('span', { class: 'tw' }), h('span', { class: 'ic', html: icon(ic) }), name, h('span', { class: 'cnt' }, '(' + n + ')'));
    row.style.paddingLeft = '4px';
    rows.push(row);
  }
  tree.replaceChildren(...rows);
}

function folderIconEl(path, depth) {
  if (depth === 0) return iconEl('vault');
  const fi = state.folderIcons[path];
  // KeePass folder icons: custom image or standard icon; else a folder (open when selected)
  if (fi && (fi.custom || (fi.id !== 48 && fi.id !== 49))) return kpIconEl(fi, 'folder');
  return iconEl(state.folder === path ? 'folderOpen' : 'folder');
}

const matchFolder = (f) => (e) => {
  if (f === SHARED_WITH_ME) return e.permission !== 'owner';
  if (f === SHARED_BY_ME) return e.permission === 'owner' && e.shared;
  if (!f) return true;
  const ef = (e.folder || '').split('/').map((s) => s.trim()).filter(Boolean).join('/');
  return ef === f || ef.startsWith(f + '/');
};

// ============================================================== List

const COLUMNS = [
  { key: 'title', label: () => t('ui/field-title'), width: '24%' },
  { key: 'username', label: () => t('ui/field-username'), width: '16%' },
  { key: 'password', label: () => t('ui/field-password'), width: '11%' },
  { key: 'url', label: () => t('ui/field-url'), width: '19%', cls: 'col-url' },
  { key: 'notes', label: () => t('ui/field-notes'), width: '16%', cls: 'col-notes' },
  { key: 'modified', label: () => t('ui/field-modified'), width: '14%', cls: 'col-mod' },
];

function visible() {
  const q = state.search.trim().toLowerCase();
  const f = matchFolder(state.folder);
  const list = state.entries.filter((e) => f(e) && (!q ||
    [e.title, e.username, e.url, e.notes, e.folder].some((v) => (v || '').toLowerCase().includes(q))));
  const { key, dir } = state.sort;
  return list.sort((a, b) => dir * String(a[key] || '').localeCompare(String(b[key] || ''), i18n.lang || 'en', { sensitivity: 'base' }));
}

function renderList() {
  $('#listhead').replaceChildren(...COLUMNS.map((c) => {
    const th = h('th', { class: c.cls || '', onclick: () => {
      state.sort = { key: c.key, dir: state.sort.key === c.key ? -state.sort.dir : 1 }; renderList();
    } }, c.label(), state.sort.key === c.key ? h('span', { class: 'arrow' }, state.sort.dir > 0 ? '▲' : '▼') : '');
    th.style.width = c.width;
    return th;
  }));
  const rows = visible();
  $('#empty').hidden = rows.length > 0;
  $('#listbody').replaceChildren(...rows.map((e) => {
    const badges = [];
    if (e.warnings && e.warnings.length) badges.push(h('span', { class: 'badge warn', title: e.warnings.join('\n'), html: icon('warn') }));
    if (!canEdit(e)) badges.push(h('span', { class: 'badge', title: t('ui/read-only'), html: icon('readonly') }));
    if (e.shared) badges.push(h('span', { class: 'badge', title: t('ui/shared'), html: icon('shared') }));
    const tr = h('tr', {
      class: e.id === state.selected ? 'sel' : '',
      onmousedown: () => { state.selected = e.id; renderSelection(); },
      ondblclick: () => entryDialog(e.id),
      oncontextmenu: (ev) => {
        ev.preventDefault(); state.selected = e.id; renderSelection(); $('#listwrap').focus();
        buildMenu(['user', 'pw', 'url', 'urlcopy', '-', 'add', 'edit', 'dup', 'del', '-', 'share', 'history'], ev.clientX, ev.clientY);
      },
    },
    h('td', {}, h('span', { class: 'ti' }, entryIconEl(e), e.title || t('ui/untitled'), ...badges)),
    h('td', {}, e.username),
    h('td', {}, '********'),
    h('td', { class: 'col-url' }, e.url),
    h('td', { class: 'col-notes' }, (e.notes || '').split('\n')[0]),
    h('td', { class: 'col-mod' }, fmtDate(e.modified)));
    tr.dataset.id = e.id;
    return tr;
  }));
}

function renderSelection() {
  document.querySelectorAll('#listbody tr').forEach((tr) => tr.classList.toggle('sel', tr.dataset.id === state.selected));
  renderDetails(); renderToolbar(); renderStatus();
}

function renderDetails() {
  const e = sel();
  const d = $('#details');
  if (!e) { d.replaceChildren(); return; }
  const row = (k, v) => h('tr', {}, h('td', { class: 'k' }, k + ':'), h('td', {}, v));
  const url = e.url && /^https?:\/\//i.test(e.url)
    ? h('a', { href: '#', onclick: (ev) => { ev.preventDefault(); openUrl(); } }, e.url) : e.url;
  d.replaceChildren(h('table', {},
    row(t('ui/field-folder'), e.folder || state.org),
    row(t('ui/field-title'), h('span', { class: 'ti' }, entryIconEl(e), e.title)),
    row(t('ui/field-username'), e.username),
    row(t('ui/field-password'), h('span', { class: 'mono' }, '********')),
    row(t('ui/field-url'), url),
    row(t('ui/field-notes'), e.notes),
    row(t('ui/field-modified'), fmtDate(e.modified) + (e['modified-by'] ? t('ui/modified-by', { user: e['modified-by'] }) : '') +
      t('ui/version-suffix', { version: e.version })),
    isLocal() ? null : row(t('ui/your-permission'), PERMS()[e.permission] + (e.shared ? t('ui/shared-suffix') : '')),
    ...(e.warnings || []).map((w) => h('tr', {}, h('td', { class: 'k warnline' }, t('ui/warning') + ':'), h('td', { class: 'warnline' }, w)))));
}

function renderStatus() {
  const n = visible().length;
  $('#st-count').textContent = state.selected ? tn('ui/status-selected-of', n) : tn('ui/status-entries', n);
  if (isLocal()) {
    $('#st-sync').textContent = t('ui/status-local-file') + (state.link ? t('ui/status-link-requested') : '');
    $('#st-user').textContent = state.file;
    return;
  }
  let sync = state.online ? t('ui/status-online') : t('ui/status-offline');
  if (state.lastSync) sync += t('ui/status-last-sync', { time: state.lastSync.toLocaleTimeString(dateLocale(), { timeStyle: 'short' }) });
  if (state.pending) sync += tn('ui/status-pending', state.pending);
  if (state.conflicts) sync += tn('ui/status-conflicts', state.conflicts);
  $('#st-sync').textContent = sync;
  $('#st-user').textContent = (state.displayName || state.me || '') + ' @ ' + state.org;
}

function render() {
  renderMenubar(); renderToolbar(); renderTree(); renderList(); renderDetails(); renderStatus();
}

// ============================================================== Actions

let clipTimer;
async function copy(field, label) {
  const e = sel(); if (!e) return;
  try {
    const r = await api('copy', { id: e.id, field });
    let secs = r['clear-after'] || 12;
    if (!r.copied) {
      await navigator.clipboard.writeText(r.value);
      setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), secs * 1000);
    }
    clearInterval(clipTimer);
    const st = $('#st-clip');
    const tick = () => {
      st.textContent = t('ui/clipboard-countdown', { label, secs });
      if (secs-- <= 0) { clearInterval(clipTimer); st.textContent = ''; }
    };
    tick(); clipTimer = setInterval(tick, 1000);
  } catch (e2) { fail(e2); }
}

async function openUrl() {
  const e = sel(); if (!e || !e.url) return;
  const u = /^[a-z][a-z0-9+.-]*:/i.test(e.url) ? e.url : 'https://' + e.url;
  if (!/^https?:/i.test(u)) return toast(t('ui/only-http-urls'), true);
  window.open(u, '_blank', 'noopener,noreferrer');
}

async function duplicate() {
  const e = sel(); if (!e) return;
  try { state.selected = await api('duplicate', { id: e.id }); await refresh(); toast(t('ui/entry-duplicated')); } catch (x) { fail(x); }
}

async function remove() {
  const e = sel(); if (!e) return;
  const ok = await confirmDialog(t('ui/entry-delete'), t('ui/entry-delete-confirm', { title: e.title || '' }) +
    (e.shared ? '\n\n' + t('ui/entry-delete-shared') : ''), t('ui/delete'));
  if (!ok) return;
  try { await api('delete', { id: e.id }); state.selected = null; await refresh(); } catch (x) { fail(x); }
}

// ============================================================== Dialogs

const dialogStack = [];

function dialog({ title, heading, sub, iconName = 'entry', iconNode, body, buttons, width, onClose }) {
  const ov = h('div', { class: 'overlay' });
  const close = (v) => { ov.remove(); dialogStack.splice(dialogStack.indexOf(api_), 1); if (onClose) onClose(v); };
  const api_ = { close, el: ov };
  const dlg = h('div', { class: 'dialog', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
    h('div', { class: 'titlebar' }, h('span', { class: 'ic', html: icon(iconName) }), h('span', { class: 't' }, title),
      h('button', { class: 'x', title: t('ui/close'), html: icon('x'), onclick: () => close(null) })),
    heading ? h('div', { class: 'banner' }, iconNode ? h('span', { class: 'big' }, iconNode) : h('span', { class: 'big', html: icon(iconName) }),
      h('div', {}, h('h2', {}, heading), sub ? h('p', {}, sub) : null)) : null,
    h('div', { class: 'body' }, body),
    buttons ? h('div', { class: 'buttons' }, buttons) : null);
  if (width) dlg.style.width = width;
  ov.append(dlg);
  $('#dialogs').append(ov);
  dialogStack.push(api_);
  setTimeout(() => {
    const f = dlg.querySelector('[autofocus]:not([disabled]), input:not([disabled]):not([type=checkbox]), .btn.primary');
    if (f) f.focus();
  }, 0);
  return api_;
}

function closeAllDialogs() { while (dialogStack.length) dialogStack[dialogStack.length - 1].close(null); }

function confirmDialog(title, text, okLabel) {
  return new Promise((resolve) => {
    let d;
    const ok = h('button', { class: 'btn primary danger', onclick: () => { d.close(true); } }, okLabel || 'OK');
    d = dialog({
      title, iconName: 'warn', body: h('div', {}, ...text.split('\n').map((l) => h('div', {}, l || ' '))),
      buttons: [ok, h('button', { class: 'btn', onclick: () => d.close(false) }, t('ui/cancel'))],
      onClose: (v) => resolve(!!v),
    });
    setTimeout(() => ok.focus(), 0);
  });
}

function aboutDialog() {
  let d;
  d = dialog({
    title: t('ui/about-title'), heading: 'cljpass', sub: t('ui/about-sub'), iconName: 'vault',
    body: h('div', {},
      h('p', {}, t('ui/about-crypto')),
      isLocal()
        ? h('p', {}, t('ui/about-local-before'), h('b', {}, state.file), t('ui/about-local-after'))
        : h('p', {}, t('ui/about-signed-in-before'), h('b', {}, state.me || ''), t('ui/about-signed-in-middle'), h('b', {}, state.org), t('ui/about-signed-in-after')),
      h('p', { class: 'hint' }, t('ui/about-shortcuts'))),
    buttons: [h('button', { class: 'btn primary', onclick: () => d.close() }, 'OK')],
  });
}

// ---------------------------------------------------------------- Entry

async function entryDialog(id, startTab = 'entry') {
  let entry = { title: '', username: '', password: '', url: '', notes: '', folder: '', expires: '', 'custom-fields': [], permission: 'owner' };
  if (id) {
    try { entry = await api('entry', { id }); } catch (e) { return fail(e); }
  } else if (state.folder && !state.folder.startsWith('\u0000')) {
    entry.folder = state.folder;
  }
  const editable = !id || canEdit(entry);
  const owner = !id || isOwner(entry);
  const dis = !editable;

  // --- Tab entry
  const f = {
    title: h('input', { type: 'text', value: entry.title, disabled: dis, autofocus: true }),
    username: h('input', { type: 'text', value: entry.username, disabled: dis, autocomplete: 'off' }),
    password: h('input', { type: 'password', class: 'pw', value: entry.password, disabled: dis, autocomplete: 'new-password' }),
    repeat: h('input', { type: 'password', class: 'pw', value: entry.password, disabled: dis, autocomplete: 'new-password' }),
    url: h('input', { type: 'text', value: entry.url, disabled: dis }),
    notes: h('textarea', { disabled: dis }, entry.notes),
    folder: h('input', { type: 'text', value: entry.folder, disabled: dis, placeholder: t('ui/folder-placeholder') }),
    expires: h('input', { type: 'date', value: entry.expires, disabled: dis }),
  };
  const qbar = h('div');
  const qtext = h('span', { class: 'hint' });
  const updateQuality = async () => {
    try {
      const { quality } = await api('quality', { password: f.password.value });
      qbar.style.width = Math.min(100, quality / 1.28) + '%';
      qtext.textContent = t('ui/quality-bits', { bits: quality });
    } catch { /* ignore */ }
  };
  f.password.addEventListener('input', updateQuality);
  let masked = true;
  const eye = h('button', { class: 'btn icon', type: 'button', title: t('ui/password-show-hide'), html: icon('eye'), onclick: () => {
    masked = !masked;
    f.password.type = f.repeat.type = masked ? 'password' : 'text';
    f.repeat.parentElement.previousElementSibling.hidden = f.repeat.parentElement.hidden = !masked;
  } });
  const genBtn = h('button', { class: 'btn icon', type: 'button', title: t('ui/password-generate'), html: icon('gen'), disabled: dis,
    onclick: () => generatorDialog((pw) => { f.password.value = pw; f.repeat.value = pw; updateQuality(); }) });

  const notices = [];
  if (!editable) notices.push(h('div', { class: 'notice info', html: icon('readonly') }, h('span', {}, t('ui/read-only-notice'))));
  for (const w of entry.warnings || []) notices.push(h('div', { class: 'notice', html: icon('warn') }, h('span', {}, w)));

  const tabEntry = h('div', {}, notices,
    h('div', { class: 'form' },
      lbl(t('ui/field-title')), f.title,
      lbl(t('ui/field-username')), f.username,
      lbl(t('ui/field-password')), h('div', { class: 'row' }, f.password, eye, genBtn),
      lbl(t('ui/repeat')), h('div', { class: 'row' }, f.repeat),
      lbl(t('ui/quality')), h('div', { class: 'row' }, h('div', { class: 'quality' }, qbar), qtext),
      lbl(t('ui/field-url')), f.url,
      lbl(t('ui/field-notes')), f.notes,
      lbl(t('ui/field-folder')), f.folder,
      lbl(t('ui/field-expires')), f.expires));
  updateQuality();

  // --- Tab advanced (custom fields)
  const custom = (entry['custom-fields'] || []).map((c) => ({ ...c }));
  const customBody = h('div');
  const renderCustom = () => {
    customBody.replaceChildren(
      h('table', { class: 'grid' }, h('thead', {}, h('tr', {}, h('th', {}, t('ui/custom-name')), h('th', {}, t('ui/custom-value')), h('th', {}, t('ui/custom-protected')), h('th', {}))),
        h('tbody', {}, ...custom.map((c, i) => h('tr', {},
          h('td', {}, h('input', { class: 'field', value: c.name, disabled: dis, oninput: (ev) => (c.name = ev.target.value) })),
          h('td', {}, h('input', { class: 'field', type: c.protected ? 'password' : 'text', value: c.value, disabled: dis, oninput: (ev) => (c.value = ev.target.value) })),
          h('td', {}, h('input', { type: 'checkbox', checked: !!c.protected, disabled: dis, onchange: (ev) => { c.protected = ev.target.checked; renderCustom(); } })),
          h('td', {}, h('button', { class: 'btn icon', type: 'button', disabled: dis, title: t('ui/remove'), html: icon('del'), onclick: () => { custom.splice(i, 1); renderCustom(); } })))))),
      h('div', {}, h('button', { class: 'btn', type: 'button', disabled: dis, onclick: () => { custom.push({ name: '', value: '', protected: false }); renderCustom(); } }, t('ui/add'))));
  };
  renderCustom();
  const tabAdv = h('div', {}, h('p', { class: 'hint' }, t('ui/custom-fields-hint')), customBody);

  // --- Tab share
  const share = id && !isLocal() ? await shareEditor(id, owner) : null;
  const tabShare = share ? share.el : h('div', { class: 'hint' }, t('ui/share-save-first'));

  // --- Tab history
  const tabHistory = h('div', { class: 'hint' }, t('ui/loading'));
  const loadHistory = async () => {
    try {
      const hist = await api('history', { id });
      tabHistory.className = '';
      tabHistory.replaceChildren(h('table', { class: 'grid' },
        h('thead', {}, h('tr', {}, h('th', {}, t('ui/version')), h('th', {}, t('ui/date')), h('th', {}, t('ui/author')), h('th', {}, t('ui/status')))),
        h('tbody', {}, ...hist.map((v) => h('tr', {},
          h('td', {}, String(v.version)), h('td', {}, fmtDate(v.date)), h('td', {}, v.author || ''),
          h('td', { class: v.valid ? '' : 'bad' }, v.valid ? (v.deleted ? t('ui/history-deleted') : t('ui/history-valid')) : t('ui/history-rejected', { reason: v.reason })))))));
    } catch (e) { tabHistory.textContent = e.message; }
  };

  // --- Tab properties
  const tabProps = h('div', { class: 'form' },
    lbl('ID'), h('span', { class: 'mono' }, id || t('ui/new-id')),
    lbl(t('ui/version')), h('span', {}, String(entry.version || '-')),
    lbl(t('ui/field-modified')), h('span', {}, fmtDate(entry.modified) + (entry['modified-by'] ? t('ui/modified-by', { user: entry['modified-by'] }) : '')),
    isLocal() ? null : lbl(t('ui/your-permission')), isLocal() ? null : h('span', {}, PERMS()[entry.permission] || ''));

  const panels = isLocal()
    ? { entry: tabEntry, adv: tabAdv, history: tabHistory, props: tabProps }
    : { entry: tabEntry, adv: tabAdv, share: tabShare, history: tabHistory, props: tabProps };
  if (!panels[startTab]) startTab = 'entry';
  const labels = { entry: t('ui/tab-entry'), adv: t('ui/tab-advanced'), share: t('ui/tab-share'), history: t('ui/tab-history'), props: t('ui/tab-properties') };
  const panel = h('div', { class: 'tabpanel' });
  const tabs = h('div', { class: 'tabs', role: 'tablist' });
  const show = (k) => {
    tabs.querySelectorAll('.tab').forEach((t) => t.classList.toggle('on', t.dataset.k === k));
    panel.replaceChildren(panels[k]);
    if (k === 'history' && id) loadHistory();
  };
  for (const k of Object.keys(panels)) {
    const t = h('button', { class: 'tab', type: 'button', role: 'tab', disabled: !id && (k === 'history'), onclick: () => show(k) }, labels[k]);
    t.dataset.k = k; tabs.append(t);
  }
  show(startTab);

  let d;
  const okBtn = h('button', { class: 'btn primary', onclick: async () => {
    if (editable && f.password.type === 'password' && f.password.value !== f.repeat.value) {
      show('entry'); f.repeat.focus(); return toast(t('ui/password-mismatch'), true);
    }
    okBtn.disabled = true;
    try {
      let savedId = id;
      if (editable) {
        const payload = {
          id: id || '', title: f.title.value, username: f.username.value, password: f.password.value, url: f.url.value,
          notes: f.notes.value, folder: f.folder.value, expires: f.expires.value,
          'custom-fields': custom.filter((c) => c.name.trim()),
        };
        const changed = !id || ['title', 'username', 'password', 'url', 'notes', 'folder', 'expires'].some((k) => (entry[k] || '') !== payload[k])
          || JSON.stringify(entry['custom-fields'] || []) !== JSON.stringify(payload['custom-fields']);
        if (changed) savedId = await api('save', payload);
      }
      if (share && share.changed()) await share.save();
      state.selected = savedId;
      d.close(true);
      await refresh();
      if (!id) { toast(t('ui/entry-created')); }
    } catch (e) { fail(e); okBtn.disabled = false; }
  } }, 'OK');

  d = dialog({
    title: id ? (editable ? t('ui/entry-edit') : t('ui/entry-view')) : t('ui/entry-add'),
    heading: id ? (entry.title || t('ui/untitled')) : t('ui/entry-new'),
    iconNode: id ? entryIconEl(entry) : null,
    sub: isLocal() ? (entry.folder || state.org) : id ? (PERMS()[entry.permission] + (entry.folder ? ' - ' + entry.folder : '')) : t('ui/entry-new-sub'),
    body: h('div', {}, tabs, panel), width: '620px',
    buttons: [
      id ? h('button', { class: 'btn left', type: 'button', onclick: async () => { d.close(); state.selected = id; await duplicate(); } }, t('ui/duplicate')) : null,
      okBtn, h('button', { class: 'btn', onclick: () => d.close(null) }, t('ui/cancel'))],
  });
  d.el.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && ev.target.tagName !== 'TEXTAREA' && ev.target.tagName !== 'BUTTON' && !ev.target.closest('.share-add')) {
      ev.preventDefault(); okBtn.click();
    }
  });
}

// ---------------------------------------------------------------- Sharing (modelled on Passbolt)

async function shareEditor(id, owner) {
  const [aclInfo, principals] = await Promise.all([api('acl', { id }), owner ? api('principals') : Promise.resolve([])]);
  const acl = aclInfo.acl.map((a) => ({ ...a }));
  const original = JSON.stringify(acl.map((a) => [a.principal, a.permission]));
  const list = h('div', { class: 'share-list' });
  const warn = h('div', { class: 'err' });

  const render = () => {
    const owners = acl.filter((a) => a.permission === 'owner').length;
    warn.textContent = owners === 0 ? t('ui/owner-required') : '';
    list.replaceChildren(...acl.map((a, i) => {
      const self = a.principal === 'u:' + state.me;
      const sub = a.kind === 'group' ? tn('ui/group-members', a.members || 0) : (self ? t('ui/you') : t('ui/user')) + (a.active ? '' : t('ui/deactivated-suffix'));
      const select = h('select', { disabled: !owner, 'aria-label': t('ui/permission-for', { name: a.display }),
        onchange: (ev) => { a.permission = ev.target.value; render(); } },
      ...Object.entries(PERMS()).map(([k, v]) => h('option', { value: k, selected: a.permission === k }, v)));
      return h('div', { class: 'share-row' }, avatar(a),
        h('div', { class: 'who' }, h('div', { class: 'n' }, a.display), h('div', { class: 's' }, sub)),
        select,
        owner ? h('button', { class: 'btn icon', type: 'button', title: t('ui/remove'), html: icon('x'), onclick: () => { acl.splice(i, 1); render(); } }) : null);
    }));
    if (!acl.length) list.append(h('div', { class: 'share-row hint' }, t('ui/shared-with-nobody')));
  };

  // add people/groups
  const input = h('input', { type: 'text', placeholder: t('ui/share-add-placeholder'), 'aria-label': t('ui/share-search'), disabled: !owner });
  const sug = h('div', { class: 'suggest', hidden: true });
  let active = 0; let matches = [];
  const pick = (p) => {
    acl.push({ ...p, permission: 'read' });
    input.value = ''; sug.hidden = true; render(); input.focus();
  };
  const updateSug = () => {
    const q = input.value.trim().toLowerCase();
    const present = new Set(acl.map((a) => a.principal));
    matches = q ? principals.filter((p) => !present.has(p.principal) &&
      (p.display.toLowerCase().includes(q) || p.name.toLowerCase().includes(q))).slice(0, 8) : [];
    active = 0;
    sug.hidden = matches.length === 0;
    sug.replaceChildren(...matches.map((p, i) => h('div', { class: 'share-row' + (i === active ? ' active' : ''), onmousedown: (ev) => { ev.preventDefault(); pick(p); } },
      avatar(p), h('div', { class: 'who' }, h('div', { class: 'n' }, p.display),
        h('div', { class: 's' }, p.kind === 'group' ? tn('ui/group-members', p.members || 0) : p.name)))));
  };
  input.addEventListener('input', updateSug);
  input.addEventListener('blur', () => setTimeout(() => (sug.hidden = true), 100));
  input.addEventListener('keydown', (ev) => {
    if (sug.hidden) return;
    if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
      ev.preventDefault();
      active = (active + (ev.key === 'ArrowDown' ? 1 : -1) + matches.length) % matches.length;
      [...sug.children].forEach((c, i) => c.classList.toggle('active', i === active));
    } else if (ev.key === 'Enter') { ev.preventDefault(); if (matches[active]) pick(matches[active]); }
  });

  render();
  const el = h('div', {},
    owner ? null : h('div', { class: 'notice info', html: icon('readonly') }, h('span', {}, t('ui/share-owner-only'))),
    list,
    owner ? h('div', { class: 'share-add' }, input, sug) : null,
    warn,
    h('p', { class: 'hint' }, t('ui/share-revoke-hint')));
  return {
    el,
    changed: () => JSON.stringify(acl.map((a) => [a.principal, a.permission])) !== original,
    save: async () => {
      if (!acl.some((a) => a.permission === 'owner')) throw new Error(t('ui/owner-required'));
      await api('set-acl', { id, acl: acl.map((a) => ({ principal: a.principal, permission: a.permission })) });
    },
  };
}

// ---------------------------------------------------------------- Password generator (like KeePass)

function generatorDialog(onUse) {
  const opts = { length: 20, upper: true, lower: true, digits: true, minus: false, underline: false, space: false, special: true, brackets: false, 'exclude-look-alike': false };
  try { Object.assign(opts, JSON.parse(localStorage.getItem('av-gen') || '{}')); } catch { /* ignore */ }
  const out = h('input', { type: 'text', class: 'pw field', readonly: true });
  const q = h('span', { class: 'hint' });
  const gen = async () => {
    try {
      const r = await api('generate', opts);
      out.value = r.password; q.textContent = t('ui/quality-bits', { bits: r.quality });
      try { localStorage.setItem('av-gen', JSON.stringify(opts)); } catch { /* ignore */ }
    } catch (e) { fail(e); }
  };
  const len = h('input', { type: 'number', min: 4, max: 256, value: opts.length, oninput: (ev) => { opts.length = +ev.target.value || 20; gen(); } });
  const cb = (k, label) => h('label', {}, h('input', { type: 'checkbox', checked: !!opts[k], onchange: (ev) => { opts[k] = ev.target.checked; gen(); } }), label);
  let d;
  d = dialog({
    title: t('ui/generator-title'), heading: t('ui/password-generate'), sub: t('ui/generator-sub'), iconName: 'gen', width: '480px',
    body: h('div', { class: 'form' },
      lbl(t('ui/gen-length')), len,
      h('div', { class: 'full checks' },
        cb('upper', t('ui/gen-upper')), cb('lower', t('ui/gen-lower')),
        cb('digits', t('ui/gen-digits')), cb('minus', t('ui/gen-minus')),
        cb('underline', t('ui/gen-underline')), cb('space', t('ui/gen-space')),
        cb('special', t('ui/gen-special')), cb('brackets', t('ui/gen-brackets')),
        cb('exclude-look-alike', t('ui/gen-exclude-look-alike'))),
      lbl(t('ui/gen-preview')), h('div', { class: 'row' }, out,
        h('button', { class: 'btn icon', type: 'button', title: t('ui/gen-regenerate'), html: icon('sync'), onclick: gen })),
      lbl(t('ui/quality')), q),
    buttons: onUse
      ? [h('button', { class: 'btn primary', onclick: () => { onUse(out.value); d.close(); } }, t('ui/apply')), h('button', { class: 'btn', onclick: () => d.close() }, t('ui/cancel'))]
      : [h('button', { class: 'btn primary', onclick: async () => {
        try { await navigator.clipboard.writeText(out.value); toast(t('ui/copied-to-clipboard')); } catch (e) { fail(e); }
      } }, t('ui/copy')), h('button', { class: 'btn', onclick: () => d.close() }, t('ui/close'))],
  });
  gen();
}

// ---------------------------------------------------------------- KeePass import/export

function readBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).replace(/^data:[^,]*,/, ''));
    r.onerror = () => reject(new Error(t('ui/file-unreadable')));
    r.readAsDataURL(file);
  });
}

function importDialog() {
  const file = h('input', { type: 'file', accept: '.kdbx' });
  const pw = h('input', { type: 'password', autocomplete: 'off' });
  const kf = h('input', { type: 'file' });
  const err = h('div', { class: 'err' });
  let d;
  const ok = h('button', { class: 'btn primary', onclick: async () => {
    err.textContent = '';
    if (!file.files[0]) { err.textContent = t('ui/import-choose-file'); return; }
    ok.disabled = true; ok.textContent = t('ui/importing');
    try {
      const r = await api('kdbx-import', {
        name: file.files[0].name, data: await readBase64(file.files[0]), password: pw.value,
        keyfile: kf.files[0] ? await readBase64(kf.files[0]) : '',
      });
      d.close(true);
      await refresh();
      toast(tn('ui/imported', r.imported));
    } catch (e) { err.textContent = e.message; ok.disabled = false; ok.textContent = t('ui/import'); }
  } }, t('ui/import'));
  d = dialog({
    title: t('ui/kdbx-import-title'), heading: t('ui/kdbx-import-title'), iconName: 'import', width: '520px',
    sub: t('ui/kdbx-import-sub'),
    body: h('div', {},
      h('div', { class: 'form' },
        lbl(t('ui/file')), file,
        lbl(t('ui/field-password')), pw,
        lbl(t('ui/keyfile')), kf),
      err,
      h('p', { class: 'hint' }, isLocal() ? t('ui/kdbx-import-hint-local') : t('ui/kdbx-import-hint-server'))),
    buttons: [ok, h('button', { class: 'btn', onclick: () => d.close() }, t('ui/cancel'))],
  });
}

function exportDialog() {
  const pw = h('input', { type: 'password', autocomplete: 'new-password' });
  const pw2 = h('input', { type: 'password', autocomplete: 'new-password' });
  const kf = h('input', { type: 'file' });
  const err = h('div', { class: 'err' });
  let d;
  const ok = h('button', { class: 'btn primary', onclick: async () => {
    err.textContent = '';
    if (pw.value !== pw2.value) { err.textContent = t('ui/password-mismatch'); return; }
    if (!pw.value && !kf.files[0]) { err.textContent = t('ui/password-or-keyfile-required'); return; }
    ok.disabled = true; ok.textContent = t('ui/exporting');
    try {
      const r = await api('kdbx-export', { password: pw.value, keyfile: kf.files[0] ? await readBase64(kf.files[0]) : '' });
      const bin = atob(r.data);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
      const a = h('a', { href: url, download: 'cljpass-' + new Date().toISOString().slice(0, 10) + '.kdbx' });
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      d.close(true);
      toast(tn('ui/exported', r.count));
    } catch (e) { err.textContent = e.message; ok.disabled = false; ok.textContent = t('ui/export'); }
  } }, t('ui/export'));
  d = dialog({
    title: t('ui/kdbx-export-title'), heading: t('ui/kdbx-export-title'), iconName: 'export', width: '520px',
    sub: t('ui/kdbx-export-sub'),
    body: h('div', {},
      h('div', { class: 'form' },
        lbl(t('ui/new-password')), pw,
        lbl(t('ui/repeat')), pw2,
        lbl(t('ui/keyfile')), kf),
      err,
      h('p', { class: 'hint' }, isLocal() ? t('ui/kdbx-export-hint-local') : t('ui/kdbx-export-hint-server'))),
    buttons: [ok, h('button', { class: 'btn', onclick: () => d.close() }, t('ui/cancel'))],
  });
}

// ---------------------------------------------------------------- Synchronize with a file (like KeePass)

function syncFileDialog() {
  const picker = filePicker('', false);
  const pw = h('input', { type: 'password', autocomplete: 'off' });
  const kf = h('input', { type: 'file' });
  const err = h('div', { class: 'err' });
  let d;
  const ok = h('button', { class: 'btn primary', onclick: async () => {
    err.textContent = '';
    if (!picker.input.value.trim()) { err.textContent = t('ui/sync-file-required'); return; }
    ok.disabled = true; ok.textContent = t('ui/syncing');
    try {
      const r = await api('sync-file', { file: picker.input.value.trim(), password: pw.value,
        keyfile: kf.files[0] ? await readBase64(kf.files[0]) : '' });
      d.close(true);
      await refresh();
      toast(t('ui/sync-file-done', { added: r.added, updated: r.updated, deleted: r.deleted }));
    } catch (e) { err.textContent = e.message; ok.disabled = false; ok.textContent = t('ui/sync'); }
  } }, t('ui/sync'));
  d = dialog({
    title: t('ui/sync'), heading: t('ui/sync-file-heading'), iconName: 'conflict', width: '560px',
    sub: t('ui/sync-file-sub'),
    body: h('div', {},
      h('div', { class: 'form' },
        lbl(t('ui/other-file')), picker.el,
        lbl(t('ui/your-password')), pw,
        lbl(t('ui/keyfile')), kf),
      err,
      h('p', { class: 'hint' }, t('ui/sync-file-hint'))),
    buttons: [ok, h('button', { class: 'btn', onclick: () => d.close() }, t('ui/cancel'))],
  });
}

// ---------------------------------------------------------------- Switching file <-> server

function connectDialog() {
  const d0 = state.defaults || {};
  const server = h('input', { type: 'url', value: d0.server || '', placeholder: t('ui/server-placeholder') });
  const hash = h('input', { type: 'text', value: d0['org-hash'] || '', placeholder: t('ui/org-hash-placeholder') });
  const user = h('input', { type: 'text', value: d0.user || state.me || '' });
  const err = h('div', { class: 'err' });
  let d;
  const ok = h('button', { class: 'btn primary', onclick: async () => {
    err.textContent = ''; ok.disabled = true;
    try {
      const l = await api('connect', { server: server.value.trim(), 'org-hash': hash.value.trim(), user: user.value.trim() });
      d.close(true);
      noteLink(l); renderStatus(); renderMenubar();
    } catch (e) { err.textContent = e.message; ok.disabled = false; }
  } }, t('ui/connect'));
  d = dialog({
    title: t('ui/connect-title'), heading: t('ui/connect-title'), iconName: 'share', width: '540px',
    sub: t('ui/connect-sub'),
    body: h('div', {},
      h('div', { class: 'form' },
        lbl(t('ui/server')), server,
        lbl(t('ui/org-hash')), hash,
        lbl(t('ui/field-username')), user),
      err,
      h('p', { class: 'hint' }, t('ui/connect-hint'))),
    buttons: [ok, h('button', { class: 'btn', onclick: () => d.close() }, t('ui/cancel'))],
  });
}

function disconnectDialog() {
  const picker = filePicker(state.file, true);
  const pw = h('input', { type: 'password', autocomplete: 'new-password' });
  const pw2 = h('input', { type: 'password', autocomplete: 'new-password' });
  const kf = h('input', { type: 'file' });
  const err = h('div', { class: 'err' });
  let d;
  const ok = h('button', { class: 'btn primary danger', onclick: async () => {
    err.textContent = '';
    if (pw.value !== pw2.value) { err.textContent = t('ui/password-mismatch'); return; }
    if (!pw.value && !kf.files[0]) { err.textContent = t('ui/master-password-or-keyfile-required'); return; }
    ok.disabled = true;
    const p = { file: picker.input.value.trim(), password: pw.value, keyfile: kf.files[0] ? await readBase64(kf.files[0]) : '' };
    for (;;) {
      try {
        const r = await api('disconnect', p);
        d.close(true);
        toast(tn('ui/disconnected', r.count));
        await boot();
        return;
      } catch (e) {
        let again = false;
        if (e.type === 'exists') again = p.overwrite = await confirmDialog(t('ui/overwrite-file-title'), e.message + '\n\n' + t('ui/overwrite-file-confirm'), t('ui/overwrite'));
        else if (e.type === 'pending-changes') again = p.force = await confirmDialog(t('ui/unsynced-changes-title'), e.message + '\n\n' + t('ui/unsynced-changes-confirm'), t('ui/disconnect-anyway'));
        else err.textContent = e.message;
        if (!again) { ok.disabled = false; return; }
      }
    }
  } }, t('ui/disconnect'));
  d = dialog({
    title: t('ui/disconnect-title'), heading: t('ui/disconnect-title'), iconName: 'export', width: '560px',
    sub: t('ui/disconnect-sub'),
    body: h('div', {},
      h('div', { class: 'form' },
        lbl(t('ui/file')), picker.el,
        lbl(t('ui/master-password')), pw,
        lbl(t('ui/repeat')), pw2,
        lbl(t('ui/keyfile')), kf),
      err,
      h('p', { class: 'hint' }, t('ui/disconnect-hint'))),
    buttons: [ok, h('button', { class: 'btn', onclick: () => d.close() }, t('ui/cancel'))],
  });
}

// ---------------------------------------------------------------- Conflicts

async function conflictsDialog() {
  let items;
  try { items = await api('conflicts'); } catch (e) { return fail(e); }
  const titleOf = (path) => {
    const m = /^entries\/([^/]+)\//.exec(path);
    const e = m && state.entries.find((x) => x.id === m[1]);
    return e ? e.title : path;
  };
  let d;
  const body = h('div', {});
  const render = () => {
    body.replaceChildren(items.length === 0
      ? h('p', {}, t('ui/no-conflicts') + ' ' + (state.pending ? tn('ui/changes-waiting', state.pending) : t('ui/all-synced')))
      : h('table', { class: 'grid' },
        h('thead', {}, h('tr', {}, h('th', {}, t('ui/entry')), h('th', {}, t('ui/problem')), h('th', {}, t('ui/date')), h('th', {}))),
        h('tbody', {}, ...items.map((c) => h('tr', {},
          h('td', {}, titleOf(c.path)), h('td', { class: 'bad' }, c.error || c.status), h('td', {}, fmtDate(c.date)),
          h('td', {}, h('div', { class: 'row' },
            c.status === 'conflict' && c.path.startsWith('entries/')
              ? h('button', { class: 'btn', onclick: () => resolve(c, 'retry'), title: t('ui/conflict-retry-hint') }, t('ui/conflict-retry')) : null,
            h('button', { class: 'btn', onclick: () => resolve(c, 'discard') }, t('ui/conflict-discard')))))))));
  };
  const resolve = async (c, action) => {
    try {
      await api('resolve', { id: c.id, action });
      items = items.filter((x) => x.id !== c.id); render(); await refresh();
    } catch (e) { fail(e); }
  };
  render();
  d = dialog({ title: t('ui/conflicts-title'), heading: t('ui/conflicts-heading'), iconName: 'conflict',
    sub: t('ui/conflicts-sub'), body, width: '640px',
    buttons: [h('button', { class: 'btn primary', onclick: () => d.close() }, t('ui/close'))] });
}

// ============================================================== Keyboard

document.addEventListener('keydown', (ev) => {
  if (!$('#app').hidden && dialogStack.length === 0) {
    const inInput = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName);
    const acts = actions();
    const run = (k) => { if (acts[k].on !== false) acts[k].run(); ev.preventDefault(); };
    const ctrl = ev.ctrlKey || ev.metaKey;
    if (ctrl && ev.key.toLowerCase() === 'f') { $('#search').focus(); $('#search').select(); ev.preventDefault(); return; }
    if (ctrl && ev.key.toLowerCase() === 'l') return run('lock');
    if (ev.key === 'F5') return run('sync');
    if (ctrl && ev.key.toLowerCase() === 'i') return run('add');
    if (inInput) return;
    if (ctrl && ev.key.toLowerCase() === 'b') return run('user');
    if (ctrl && ev.key.toLowerCase() === 'c' && !String(window.getSelection())) return run('pw');
    if (ctrl && ev.key.toLowerCase() === 'u') return run('url');
    if (ctrl && ev.key.toLowerCase() === 'k') return run('dup');
    if (ctrl && ev.key.toLowerCase() === 'e') return run('share');
    if (ev.key === 'Enter' && state.selected) return run('edit');
    if (ev.key === 'Delete' && state.selected) return run('del');
    if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
      const rows = visible(); if (!rows.length) return;
      let i = rows.findIndex((e) => e.id === state.selected);
      i = ev.key === 'ArrowDown' ? Math.min(rows.length - 1, i + 1) : Math.max(0, i - 1);
      state.selected = rows[i].id; renderSelection();
      const tr = document.querySelector('#listbody tr.sel'); if (tr) tr.scrollIntoView({ block: 'nearest' });
      ev.preventDefault();
    }
  }
});

document.addEventListener('mousedown', (ev) => { if (!ev.target.closest('#ctxmenu') && !ev.target.closest('.menubar')) closeMenu(); });
document.addEventListener('keydown', (ev) => {
  if (ev.key !== 'Escape') return;
  if (!$('#ctxmenu').hidden) { closeMenu(); ev.stopPropagation(); return; }
  // Escape closes the topmost dialog, wherever the focus is
  if (dialogStack.length) { ev.stopPropagation(); dialogStack[dialogStack.length - 1].close(null); }
}, true);
window.addEventListener('blur', closeMenu);

$('#listwrap').addEventListener('contextmenu', (ev) => {
  if (ev.target.closest('tr[data-id]')) return;
  ev.preventDefault(); state.selected = null; renderSelection(); buildMenu(['add'], ev.clientX, ev.clientY);
});
$('#listwrap').addEventListener('mousedown', (ev) => { if (!ev.target.closest('tr')) { state.selected = null; renderSelection(); } });

// Splitter between tree and list
(() => {
  const sp = $('#splitter'); const tree = $('#tree');
  sp.addEventListener('mousedown', (ev) => {
    const start = ev.clientX; const w = tree.offsetWidth;
    const move = (e) => { tree.style.width = Math.max(120, Math.min(500, w + e.clientX - start)) + 'px'; };
    const up = () => { document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); };
    document.addEventListener('mousemove', move); document.addEventListener('mouseup', up);
    ev.preventDefault();
  });
})();

// Periodically: check the lock state and synchronize
setInterval(() => { if (!$('#app').hidden && dialogStack.length === 0) doSync(true); }, 60000);
setInterval(async () => {
  if ($('#app').hidden) return;
  try {
    const st = await api('status', { background: true });
    if (st.state === 'locked') showLocked();
    else if (isLocal()) { noteLink(st.link); renderStatus(); renderMenubar(); }
  } catch { /* 423 shows the lock screen */ }
}, 30000);

boot();
