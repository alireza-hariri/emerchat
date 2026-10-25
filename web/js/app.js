import { api, upload, download } from './api.js';
import * as cx from './crypto.js';
import { saveKey, loadKey, clearKeys } from './keystore.js';
import { h, icon, linkify } from './dom.js';

const state = {
  me: null,
  canInvite: false,
  maxUpload: 0,
  privateKey: null,
  seq: 0,
  running: false,
  connected: true,
  chats: new Map(), // id -> chat (+ messages, hasMore, pending)
  users: new Map(), // id -> user, for names in system messages
  openId: null,
  plain: new Map(), // message id -> { text, file } | { error }
  keys: new Map(), // chatId -> Map(epoch -> { raw?, key })
  search: '',
  searchResults: [],
};

const $root = document.getElementById('app');
let els = {};

// ---------- helpers ----------

const pad = (n) => String(n).padStart(2, '0');
const sameDay = (a, b) => new Date(a).toDateString() === new Date(b).toDateString();
const timeOf = (ts) => { const d = new Date(ts); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; };

function shortDate(ts) {
  const d = new Date(ts), now = new Date();
  if (sameDay(ts, now)) return timeOf(ts);
  if (now - d < 6 * 864e5) return d.toLocaleDateString(undefined, { weekday: 'short' });
  return d.toLocaleDateString(undefined, { day: '2-digit', month: '2-digit', year: '2-digit' });
}

function dayLabel(ts) {
  const now = new Date();
  if (sameDay(ts, now)) return 'Today';
  if (sameDay(ts, now - 864e5)) return 'Yesterday';
  const d = new Date(ts);
  return d.toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: d.getFullYear() === now.getFullYear() ? undefined : 'numeric' });
}

function lastSeen(u) {
  if (!u.lastSeen) return 'last seen a long time ago';
  const ago = Date.now() - u.lastSeen;
  if (ago < 60_000) return 'online';
  if (ago < 3600_000) return `last seen ${Math.floor(ago / 60_000)} min ago`;
  if (sameDay(u.lastSeen, Date.now())) return `last seen at ${timeOf(u.lastSeen)}`;
  return `last seen ${shortDate(u.lastSeen)}`;
}

function initials(name) {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  return ((parts[0]?.[0] || '?') + (parts[1]?.[0] || '')).toUpperCase();
}

function avatar(id, name, size = '', kind = '') {
  if (kind === 'saved') return h('div', { class: `avatar ${size} saved` }, icon('bookmark'));
  const el = h('div', { class: `avatar ${size} c${Math.abs(id) % 7}` }, initials(name));
  const v = id > 0 && state.users.get(id)?.avatar;
  if (v) {
    el.replaceChildren(h('img', {
      src: `/api/users/${id}/avatar?v=${encodeURIComponent(v)}`, alt: '', draggable: 'false',
      onerror: () => el.replaceChildren(initials(name)),
    }));
  }
  return el;
}

const fmtDur = (s) => { s = Math.round(s || 0); return `${Math.floor(s / 60)}:${pad(s % 60)}`; };

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(1)} GB`;
}

/** The avatar for a chat: the peer's, a group photo, or the Saved Messages icon. */
function chatAvatar(chat, size = '') {
  if (isSaved(chat)) return avatar(0, '', size, 'saved');
  if (chat.kind !== 'group') return avatar(peerOf(chat).id, chatTitle(chat), size);
  const el = avatar(-chat.id, chat.title, size);
  if (chat.photo) {
    el.replaceChildren(h('img', {
      src: `/api/chats/${chat.id}/photo?v=${encodeURIComponent(chat.photo)}`, alt: '', draggable: 'false',
      onerror: () => el.replaceChildren(initials(chat.title)),
    }));
  }
  return el;
}

let toastTimer;
function toast(msg) {
  els.toast.textContent = msg;
  els.toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => els.toast.classList.remove('show'), 3000);
}

function rememberUsers(users) {
  for (const u of users) state.users.set(u.id, { ...state.users.get(u.id), ...u });
}

function userName(id) {
  if (id === state.me.id) return 'You';
  return state.users.get(id)?.displayName || 'Someone';
}

const isSaved = (c) => c.kind === 'direct' && c.members.length === 1;
const peerOf = (c) => c.members.find((m) => m.id !== state.me.id) || c.members[0];
const myMember = (c) => c.members.find((m) => m.id === state.me.id);
const othersRead = (c) => Math.max(0, ...c.members.filter((m) => m.id !== state.me.id).map((m) => m.lastRead));

function chatTitle(c) {
  if (c.kind === 'group') return c.title;
  return isSaved(c) ? 'Saved Messages' : peerOf(c).displayName;
}

// ---------- keys & decryption ----------

async function fetchGroupKeys(chat) {
  const { keys } = await api('GET', `/api/chats/${chat.id}/keys`);
  const map = state.keys.get(chat.id) || new Map();
  for (const k of keys) {
    if (map.has(k.epoch)) continue;
    try {
      const raw = await cx.unwrapGroupKey(state.privateKey, k.wrappedByKey, k.wrappedKey, k.iv, k.epoch, state.me.id);
      map.set(k.epoch, { raw, key: await cx.importGroupKey(raw) });
    } catch (e) {
      console.warn('cannot unwrap group key', chat.id, k.epoch, e);
    }
  }
  state.keys.set(chat.id, map);
  return map;
}

async function getKey(chat, epoch) {
  let map = state.keys.get(chat.id);
  if (chat.kind === 'direct') {
    if (!map) {
      const peer = peerOf(chat);
      map = new Map([[0, { key: await cx.directChatKey(state.privateKey, peer.publicKey, chat.id) }]]);
      state.keys.set(chat.id, map);
    }
    return map.get(0)?.key || null;
  }
  if (!map?.has(epoch)) map = await fetchGroupKeys(chat);
  return map.get(epoch)?.key || null;
}

async function wrapForMembers(raw, epoch, members) {
  return Promise.all(members.map((m) => cx.wrapGroupKey(state.privateKey, m.publicKey, raw, epoch, m.id)));
}

const rekeying = new Map();

// Makes sure a key exists for the group's current epoch, creating one if the
// epoch was just bumped (someone left). Concurrent clients race; the server
// accepts the first and the rest pick it up.
function ensureGroupKey(chat) {
  if (chat.kind !== 'group') return Promise.resolve();
  const tag = `${chat.id}:${chat.keyEpoch}`;
  if (rekeying.has(tag)) return rekeying.get(tag);
  const p = (async () => {
    if (await getKey(chat, chat.keyEpoch)) return;
    const raw = cx.newGroupKey();
    const keys = await wrapForMembers(raw, chat.keyEpoch, chat.members);
    try {
      await api('POST', `/api/chats/${chat.id}/rekey`, { epoch: chat.keyEpoch, keys });
      const map = state.keys.get(chat.id) || new Map();
      map.set(chat.keyEpoch, { raw, key: await cx.importGroupKey(raw) });
      state.keys.set(chat.id, map);
    } catch (e) {
      if (e.status !== 409) throw e;
      await fetchGroupKeys(chat);
    }
  })().finally(() => rekeying.delete(tag));
  rekeying.set(tag, p);
  return p;
}

function systemText(m) {
  let b = {};
  try { b = JSON.parse(m.body); } catch { /* ignore */ }
  const by = userName(m.senderId);
  switch (b.a) {
    case 'create': return `${by} created the group «${b.title}»`;
    case 'add': return `${by} added ${userName(b.u)}`;
    case 'remove': return `${by} removed ${userName(b.u)}`;
    case 'leave': return `${by} left the group`;
    case 'join': return `${by} joined the group via invite link`;
    case 'title': return `${by} renamed the group to «${b.title}»`;
    case 'photo': return b.removed ? `${by} removed the group photo` : `${by} changed the group photo`;
    default: return 'Service message';
  }
}

// Message payloads are { t: text, f?: attachment }. An attachment is
// { id, name, type, size, key, iv } plus { w, h } for images and
// { voice: true, dur } for voice messages. Senders are untrusted, so only
// well-formed attachments are kept.
function toPlain(obj) {
  const f = obj.f;
  const ok = f && typeof f === 'object' && /^[\w-]{22}$/.test(f.id) && typeof f.key === 'string' && typeof f.iv === 'string';
  const file = ok ? {
    id: f.id, key: f.key, iv: f.iv,
    name: String(f.name || 'file').slice(0, 255), type: String(f.type || ''), size: Number(f.size) || 0,
    ...(f.voice ? { voice: true, dur: Number(f.dur) || 0 } : {}),
    ...(f.w > 0 && f.h > 0 ? { w: Number(f.w), h: Number(f.h) } : {}),
  } : null;
  return { text: String(obj.t ?? ''), file };
}

function toPayload(text, file) {
  return file ? { t: text, f: file } : { t: text };
}

// Types we let the browser render inline. Everything else (SVG and HTML
// included) is only ever offered as a download.
const INLINE_IMAGE = /^image\/(png|jpeg|gif|webp|avif|bmp)$/;
const MEDIA = /^(audio|video)\/[\w.+-]+$/;
const MAX_AUTOLOAD = 15 << 20;

const isImage = (f) => !f.voice && INLINE_IMAGE.test(f.type) && f.w > 0;

function describe(p) {
  const f = p.file;
  if (!f) return p.text;
  const label = f.voice ? `Voice message (${fmtDur(f.dur)})` : isImage(f) ? 'Photo' : f.name;
  return p.text ? `${label}, ${p.text}` : label;
}

async function decrypt(chat, m) {
  if (m.kind === 'system') return { text: systemText(m) };
  const cached = state.plain.get(m.id);
  if (cached) return cached;
  let res;
  try {
    const key = await getKey(chat, m.epoch);
    if (!key) {
      res = { error: chat.kind === 'group' ? 'Encrypted before you joined' : 'Waiting for key…' };
      // A key missing for an older epoch never arrives; for the current one it may.
      if (chat.kind === 'group' && m.epoch < chat.keyEpoch) state.plain.set(m.id, res);
      return res;
    }
    const obj = await cx.decryptMessage(key, m.ciphertext, m.iv, cx.messageAAD(m.chatId, m.senderId, m.epoch));
    res = toPlain(obj);
  } catch (e) {
    console.warn('decrypt failed', m.id, e);
    res = { error: 'Unable to decrypt this message' };
  }
  state.plain.set(m.id, res);
  return res;
}

async function decryptAll(chat) {
  const list = [...(chat.messages || [])];
  if (chat.lastMessage) list.push(chat.lastMessage);
  for (const m of list) await decrypt(chat, m);
}

function plainOf(m) {
  if (m.kind === 'system') return { text: systemText(m), system: true };
  return state.plain.get(m.id) || { error: '…' };
}

// ---------- data ----------

// Merges server chat data into the existing object (kept stable so in-flight
// loads and open views keep pointing at the live chat).
function adoptChat(c) {
  rememberUsers(c.members);
  const prev = state.chats.get(c.id);
  if (prev) return Object.assign(prev, c);
  const chat = { ...c, messages: null, hasMore: true, pending: [] };
  state.chats.set(c.id, chat);
  return chat;
}

async function loadChats() {
  const r = await api('GET', '/api/chats');
  state.seq = r.seq;
  const keep = new Set(r.chats.map((c) => c.id));
  for (const id of state.chats.keys()) if (!keep.has(id)) state.chats.delete(id);
  for (const c of r.chats) {
    const chat = adoptChat(c);
    chat.messages = null; // reload lazily; we may have missed updates
    await decryptAll(chat).catch(() => {});
  }
  if (state.openId && !state.chats.has(state.openId)) closeChat();
  else if (state.openId) await loadMessages(state.chats.get(state.openId));
  render();
}

async function refreshChat(id) {
  try {
    const { chat: c } = await api('GET', `/api/chats/${id}`);
    const chat = adoptChat(c);
    if (chat.kind === 'group') await ensureGroupKey(chat).catch((e) => console.warn(e));
    await decryptAll(chat);
    return chat;
  } catch (e) {
    if (e.status === 404) { dropChat(id); return null; }
    throw e;
  }
}

function dropChat(id) {
  state.chats.delete(id);
  state.keys.delete(id);
  if (state.openId === id) closeChat();
}

async function loadMessages(chat, older = false) {
  if (chat.loading) return;
  chat.loading = true;
  try {
    const before = older && chat.messages?.length ? chat.messages[0].id : 0;
    const r = await api('GET', `/api/chats/${chat.id}/messages?limit=50${before ? `&before=${before}` : ''}`);
    for (const m of r.messages) await decrypt(chat, m);
    chat.messages = older ? [...r.messages, ...(chat.messages || [])] : r.messages;
    chat.hasMore = r.hasMore;
  } finally {
    chat.loading = false;
  }
}

function addMessage(chat, m) {
  chat.pending = chat.pending.filter((p) => !(m.clientId && p.clientId === m.clientId && m.senderId === state.me.id));
  if (chat.messages && !chat.messages.some((x) => x.id === m.id)) {
    chat.messages.push(m);
    chat.messages.sort((a, b) => a.id - b.id);
  }
  // Not new if a chat refresh already counted it.
  const isNew = !chat.lastMessage || m.id > chat.lastMessage.id;
  if (isNew) chat.lastMessage = m;
  // Sending implies having read the chat (the server records the same).
  const sender = chat.members.find((x) => x.id === m.senderId);
  if (sender && m.kind === 'msg') sender.lastRead = Math.max(sender.lastRead, m.id);
  const me = myMember(chat);
  if (m.senderId !== state.me.id && isNew && m.id > (me?.lastRead || 0)) {
    chat.unread = (chat.unread || 0) + 1;
  }
}

// ---------- long polling ----------

let pollAbort = null;
let wakeSleep = null;

function sleep(ms) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    wakeSleep = () => { clearTimeout(t); resolve(); };
  });
}

async function pollLoop() {
  let backoff = 1000;
  while (state.running) {
    try {
      pollAbort = new AbortController();
      const r = await api('GET', `/api/updates?after=${state.seq}&timeout=25`, undefined, { signal: pollAbort.signal });
      setConnected(true);
      backoff = 1000;
      if (r.resync) { await loadChats(); continue; }
      for (const u of r.updates) {
        try { await applyUpdate(u); } catch (e) { console.warn('update failed', u, e); }
        state.seq = u.seq;
      }
      state.seq = Math.max(state.seq, r.seq);
      if (r.updates.length) render();
    } catch (e) {
      if (!state.running) return;
      if (e.status === 401) { await logout(false); return; }
      if (e.name !== 'AbortError') setConnected(false);
      await sleep(backoff);
      backoff = Math.min(backoff * 2, 30_000);
    }
  }
}

async function applyUpdate(u) {
  const d = u.data;
  switch (u.kind) {
    case 'message': {
      let chat = state.chats.get(d.chatId);
      if (!chat) chat = await refreshChat(d.chatId);
      if (!chat) return;
      if (d.kind === 'system') await refreshChat(d.chatId); // membership may have changed
      await decrypt(chat, d);
      addMessage(chat, d);
      if (state.openId === chat.id) scheduleRead();
      return;
    }
    case 'chat':
      await refreshChat(d.chatId);
      return;
    case 'read': {
      const chat = state.chats.get(d.chatId);
      const m = chat?.members.find((x) => x.id === d.userId);
      if (!m) return;
      m.lastRead = Math.max(m.lastRead, d.upTo);
      if (d.userId === state.me.id && d.upTo >= (chat.lastMessage?.id || 0)) chat.unread = 0;
      return;
    }
    case 'edit': {
      const chat = state.chats.get(d.chatId);
      if (!chat) return;
      state.plain.delete(d.id);
      await decrypt(chat, d);
      applyEdit(chat, d);
      return;
    }
    case 'user':
      applyUser(d);
      return;
    case 'removed': {
      const chat = state.chats.get(d.chatId);
      if (chat && !chat.leaving) toast(`You are no longer a member of ${chatTitle(chat)}`);
      dropChat(d.chatId);
      return;
    }
  }
}

// applyUser spreads a profile change to every place that copies the user.
function applyUser(u) {
  rememberUsers([u]);
  if (u.id === state.me.id) Object.assign(state.me, u);
  for (const chat of state.chats.values()) {
    const m = chat.members.find((x) => x.id === u.id);
    if (m) Object.assign(m, u);
  }
}

function setConnected(ok) {
  if (state.connected === ok) return;
  state.connected = ok;
  els.conn?.classList.toggle('show', !ok);
}

// Chats the user has looked at, flushed shortly after so a burst of
// messages becomes one read receipt. Switching chats doesn't drop pending ones.
const pendingReads = new Set();
let readTimer;
function scheduleRead() {
  if (!state.openId || document.visibilityState !== 'visible') return;
  pendingReads.add(state.openId);
  clearTimeout(readTimer);
  readTimer = setTimeout(markRead, 300);
}

function markRead() {
  for (const id of pendingReads) {
    const chat = state.chats.get(id);
    const me = chat && myMember(chat);
    const upTo = chat?.lastMessage?.id;
    if (!me || !upTo) continue;
    chat.unread = 0;
    if (me.lastRead >= upTo) continue;
    me.lastRead = upTo;
    api('POST', `/api/chats/${id}/read`, { upTo }).catch((e) => console.warn(e));
  }
  pendingReads.clear();
  renderChatList();
}

// ---------- rendering: shell ----------

let renderQueued = false;
function render() {
  if (renderQueued) return;
  renderQueued = true;
  requestAnimationFrame(() => {
    renderQueued = false;
    renderChatList();
    if (state.openId) { renderHeader(); renderMessages(); }
  });
}

function buildShell() {
  els = {};
  els.search = h('input', { class: 'search-input', type: 'search', placeholder: 'Search', autocomplete: 'off', oninput: onSearch });
  els.list = h('div', { class: 'chat-list' });
  els.conn = h('div', { class: 'conn' }, h('span', { class: 'spinner' }), 'Connecting…');
  els.pane = h('main', {
    class: 'pane',
    ondragover: (e) => { if (state.openId && e.dataTransfer?.types.includes('Files')) e.preventDefault(); },
    ondrop: (e) => {
      const files = [...(e.dataTransfer?.files || [])];
      if (!state.openId || !files.length) return;
      e.preventDefault();
      attachModal(files);
    },
  });
  els.toast = h('div', { class: 'toast', role: 'status' });
  els.layout = h('div', { class: 'layout' },
    h('aside', { class: 'sidebar' },
      h('div', { class: 'sidebar-head' },
        h('button', { class: 'icon-btn', title: 'Menu', onclick: openDrawer }, icon('menu')),
        h('label', { class: 'search' }, icon('search'), els.search)),
      els.conn,
      els.list,
      h('button', { class: 'fab', title: 'New group', onclick: newGroupModal }, icon('edit'))),
    els.pane);
  $root.replaceChildren(els.layout, els.toast);
  renderEmptyPane();
}

function renderEmptyPane() {
  els.pane.replaceChildren(h('div', { class: 'empty-pane' },
    h('div', { class: 'pill' }, 'Select a chat to start messaging')));
  els.layout.classList.remove('chat-open');
}

// ---------- rendering: chat list ----------

let searchTimer;
function onSearch() {
  state.search = els.search.value.trim();
  clearTimeout(searchTimer);
  if (!state.search) { state.searchResults = []; renderChatList(); return; }
  renderChatList();
  searchTimer = setTimeout(async () => {
    const q = state.search;
    const { users } = await api('GET', `/api/users?q=${encodeURIComponent(q)}`);
    if (q !== state.search) return;
    rememberUsers(users);
    state.searchResults = users;
    renderChatList();
  }, 250);
}

function sortedChats() {
  return [...state.chats.values()].sort((a, b) =>
    (b.lastMessage?.id || 0) - (a.lastMessage?.id || 0) || b.createdAt - a.createdAt);
}

function previewOf(chat) {
  const m = chat.lastMessage;
  if (!m) return h('span', { class: 'muted' }, chat.kind === 'group' ? 'Group created' : 'No messages yet');
  const p = plainOf(m);
  if (p.system) return h('span', { class: 'muted' }, p.text);
  const text = (p.error ?? describe(p)).replace(/\s+/g, ' ');
  let who = null;
  if (m.senderId === state.me.id && !isSaved(chat)) who = 'You';
  else if (chat.kind === 'group') who = userName(m.senderId).split(' ')[0];
  return [who && h('span', { class: 'sender' }, `${who}: `), p.error ? h('i', {}, text) : text];
}

function chatRow(chat) {
  const m = chat.lastMessage;
  const mine = m && m.kind === 'msg' && m.senderId === state.me.id && !isSaved(chat);
  const ticks = mine ? icon(m.id <= othersRead(chat) ? 'checks' : 'check', 'tick') : null;
  const title = chatTitle(chat);
  return h('button', {
    class: `chat-row${chat.id === state.openId ? ' active' : ''}`,
    onclick: () => { location.hash = `#/c/${chat.id}`; },
  },
  chatAvatar(chat),
  h('div', { class: 'row-body' },
    h('div', { class: 'row-top' },
      h('span', { class: 'row-title' }, chat.kind === 'group' ? icon('group', 'kind') : null, title),
      h('span', { class: 'row-time' }, ticks, m ? shortDate(m.createdAt) : '')),
    h('div', { class: 'row-bottom' },
      h('span', { class: 'row-preview' }, previewOf(chat)),
      chat.unread > 0 ? h('span', { class: 'badge' }, chat.unread > 999 ? '999+' : chat.unread) : null)));
}

function renderChatList() {
  const q = state.search.toLowerCase();
  if (!q) {
    const rows = sortedChats().map(chatRow);
    els.list.replaceChildren(...(rows.length ? rows : [h('div', { class: 'list-empty' },
      'No chats yet.', h('br'), 'Search for people by username to start one.')]));
    return;
  }
  const chats = sortedChats().filter((c) => chatTitle(c).toLowerCase().includes(q) ||
    (c.kind === 'direct' && peerOf(c).username.includes(q)));
  const known = new Set(chats.filter((c) => c.kind === 'direct').map((c) => peerOf(c).id));
  const people = state.searchResults.filter((u) => !known.has(u.id));
  els.list.replaceChildren(
    chats.length ? h('div', { class: 'list-section' }, 'Chats') : null,
    ...chats.map(chatRow),
    people.length ? h('div', { class: 'list-section' }, 'Global search') : null,
    ...people.map((u) => h('button', { class: 'chat-row', onclick: () => startDirect(u.id) },
      u.id === state.me.id ? avatar(0, '', '', 'saved') : avatar(u.id, u.displayName),
      h('div', { class: 'row-body' },
        h('div', { class: 'row-top' }, h('span', { class: 'row-title' }, u.id === state.me.id ? 'Saved Messages' : u.displayName)),
        h('div', { class: 'row-bottom' }, h('span', { class: 'row-preview muted' }, `@${u.username}`))))),
    !chats.length && !people.length ? h('div', { class: 'list-empty' }, 'No results') : null,
  );
}

async function startDirect(peerId) {
  try {
    const { chat } = await api('POST', '/api/chats', { peerId });
    adoptChat(chat);
    els.search.value = '';
    state.search = '';
    state.searchResults = [];
    location.hash = `#/c/${chat.id}`;
  } catch (e) {
    toast(e.message);
  }
}

// ---------- rendering: open chat ----------

async function openChat(id) {
  const chat = state.chats.get(id);
  if (!chat) { location.hash = ''; return; }
  stopRecording(false);
  editing = null;
  state.openId = id;
  chat.unreadMarker = myMember(chat)?.lastRead ?? 0;
  els.header = h('header', { class: 'chat-head' });
  els.messages = h('div', { class: 'messages', onscroll: onMessagesScroll });
  els.input = h('textarea', {
    class: 'composer-input', rows: 1, placeholder: 'Message', maxlength: 4096,
    oninput: () => { autosize(); updateComposer(); },
    onkeydown: onComposerKey,
    onpaste: (e) => {
      const files = [...(e.clipboardData?.files || [])];
      if (files.length) { e.preventDefault(); attachModal(files); }
    },
  });
  els.fileInput = h('input', { type: 'file', multiple: true, hidden: true, onchange: () => {
    const files = [...els.fileInput.files];
    els.fileInput.value = '';
    if (files.length) attachModal(files);
  } });
  els.editText = h('div', { class: 'edit-text' });
  els.editBar = h('div', { class: 'edit-bar', hidden: true },
    icon('edit'),
    h('div', { class: 'grow' }, h('div', { class: 'edit-title' }, 'Edit message'), els.editText),
    h('button', { class: 'icon-btn', title: 'Cancel', onclick: cancelEdit }, icon('close')));
  els.box = h('div', { class: 'composer-box' },
    h('button', { class: 'icon-btn attach', title: 'Attach files', onclick: () => els.fileInput.click() }, icon('attach')),
    els.input);
  els.recTime = h('span', { class: 'rec-time' }, '0:00');
  els.recBox = h('div', { class: 'composer-box rec-box', hidden: true },
    h('span', { class: 'rec-dot' }), els.recTime, h('span', { class: 'grow muted' }, 'Recording…'),
    h('button', { class: 'icon-btn danger', title: 'Discard', onclick: () => stopRecording(false) }, icon('trash')));
  els.action = h('button', { class: 'send-btn', onclick: onComposerAction });
  els.pane.replaceChildren(
    els.header,
    els.messages,
    h('div', { class: 'composer' },
      h('div', { class: 'composer-main' }, els.editBar, els.box, els.recBox),
      els.action, els.fileInput));
  updateComposer();
  els.layout.classList.add('chat-open');
  renderChatList();
  renderHeader();
  if (!chat.messages) {
    els.messages.replaceChildren(h('div', { class: 'loading' }, h('span', { class: 'spinner' })));
    try { await loadMessages(chat); } catch (e) { toast(e.message); }
    if (state.openId !== id) return;
  }
  renderMessages('bottom');
  scheduleRead();
  if (matchMedia('(pointer: fine)').matches) els.input.focus();
  if (chat.kind === 'group') ensureGroupKey(chat).catch((e) => console.warn(e));
}

function closeChat() {
  stopRecording(false);
  editing = null;
  state.openId = null;
  if (location.hash.startsWith('#/c/')) history.replaceState(null, '', location.pathname);
  renderEmptyPane();
  renderChatList();
}

function autosize() {
  els.input.style.height = 'auto';
  els.input.style.height = `${Math.min(els.input.scrollHeight, 200)}px`;
}

// The round button shows send, save (while editing) or a microphone (when
// there is nothing to send).
function updateComposer() {
  if (!els.action) return;
  const rec = !!state.recording;
  els.box.hidden = rec;
  els.recBox.hidden = !rec;
  els.editBar.hidden = !editing;
  const mode = rec || (!editing && els.input.value.trim()) ? 'send' : editing ? 'check' : 'mic';
  if (els.action.dataset.mode === mode) return;
  els.action.dataset.mode = mode;
  els.action.title = { send: 'Send', check: 'Save', mic: 'Record voice message' }[mode];
  els.action.replaceChildren(icon(mode));
}

function onComposerAction() {
  const mode = els.action.dataset.mode;
  if (state.recording) stopRecording(true);
  else if (mode === 'check') saveEdit();
  else if (mode === 'mic') startRecording();
  else send();
}

function onComposerKey(e) {
  if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
    e.preventDefault();
    if (editing) saveEdit(); else send();
  } else if (e.key === 'Escape' && editing) {
    e.preventDefault();
    cancelEdit();
  } else if (e.key === 'ArrowUp' && !els.input.value && !editing) {
    // Like Telegram: arrow up in an empty composer edits your last message.
    const chat = state.chats.get(state.openId);
    const m = chat?.messages?.findLast(canEdit);
    if (m) { e.preventDefault(); startEdit(chat, m); }
  }
}

function renderHeader() {
  const chat = state.chats.get(state.openId);
  if (!chat) return;
  let status;
  if (chat.kind === 'group') status = `${chat.members.length} member${chat.members.length === 1 ? '' : 's'}`;
  else if (!isSaved(chat)) status = lastSeen(peerOf(chat));
  const title = chatTitle(chat);
  els.header.replaceChildren(
    h('button', { class: 'icon-btn back', title: 'Back', onclick: () => history.length > 1 ? history.back() : closeChat() }, icon('back')),
    h('button', { class: 'head-info', onclick: () => chatInfoModal(chat) },
      chatAvatar(chat, 'sm'),
      h('div', { class: 'head-text' },
        h('div', { class: 'head-title' }, title),
        status ? h('div', { class: `head-status${status === 'online' ? ' online' : ''}` }, status) : null)),
    h('button', { class: 'icon-btn', title: 'Info', onclick: () => chatInfoModal(chat) }, icon('info')));
}

function onMessagesScroll() {
  const chat = state.chats.get(state.openId);
  if (!chat || chat.loading || !chat.hasMore || els.messages.scrollTop > 200) return;
  loadMessages(chat, true).then(() => renderMessages('prepend')).catch((e) => toast(e.message));
}

function renderMessages(mode) {
  const chat = state.chats.get(state.openId);
  if (!chat || !chat.messages) return;
  const box = els.messages;
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
  const prevHeight = box.scrollHeight, prevTop = box.scrollTop;
  const items = [...chat.messages, ...chat.pending];
  const read = othersRead(chat);
  const group = chat.kind === 'group';
  const out = [];
  let unreadShown = false;

  if (!chat.hasMore) {
    out.push(h('div', { class: 'service' }, h('span', { class: 'pill e2e' }, icon('lock'),
      'Messages are end-to-end encrypted. The server cannot read them.')));
  }
  items.forEach((m, i) => {
    const prev = items[i - 1], next = items[i + 1];
    if (!prev || !sameDay(prev.createdAt, m.createdAt)) {
      out.push(h('div', { class: 'service sticky' }, h('span', { class: 'pill' }, dayLabel(m.createdAt))));
    }
    if (!unreadShown && m.id && m.id > chat.unreadMarker && m.senderId !== state.me.id && m.kind === 'msg') {
      unreadShown = true;
      out.push(h('div', { class: 'unread-divider' }, 'Unread messages'));
    }
    if (m.kind === 'system') {
      out.push(h('div', { class: 'service' }, h('span', { class: 'pill' }, systemText(m))));
      return;
    }
    const mine = m.senderId === state.me.id;
    const contiguous = (o) => o && o.kind !== 'system' && o.senderId === m.senderId && sameDay(o.createdAt, m.createdAt);
    const first = !contiguous(prev);
    const last = !contiguous(next);
    const p = m.pending ? { text: m.text, file: m.file } : plainOf(m);
    let status = null;
    if (mine) {
      if (m.failed) status = h('span', { class: 'failed', title: 'Not sent' }, '!');
      else if (m.pending) status = icon('clock', 'tick');
      else if (!isSaved(chat)) status = icon(m.id <= read ? 'checks' : 'check', 'tick');
    }
    const photo = p.file && isImage(p.file);
    const showName = group && !mine && first;
    let cls = 'bubble';
    if (last) cls += ' tail';
    if (p.error) cls += ' undecryptable';
    if (photo) cls += ' has-photo';
    if (photo && !p.text) cls += ' photo-only';
    if (p.file && !photo && !p.text) cls += ' file-only';
    const bubble = h('div', { class: cls, oncontextmenu: (e) => messageMenu(e, chat, m) },
      showName ? h('div', { class: `bubble-name n${m.senderId % 7}` }, userName(m.senderId)) : null,
      p.file ? attachmentView(p.file, m) : null,
      p.error ? h('span', { class: 'bubble-text' }, icon('lock', 'inline'), p.error)
        : p.text ? h('span', { class: 'bubble-text' }, linkify(p.text)) : null,
      h('span', { class: 'meta' }, m.editedAt ? h('span', { class: 'edited' }, 'edited') : null, timeOf(m.createdAt), status));
    out.push(h('div', { class: `msg ${mine ? 'out' : 'in'}${first ? ' first' : ''}${last ? ' last' : ''}` },
      group && !mine ? (last ? avatar(m.senderId, userName(m.senderId), 'xs') : h('div', { class: 'avatar-spacer' })) : null,
      bubble));
  });
  if (!items.length) {
    out.push(h('div', { class: 'no-messages' }, h('div', { class: 'pill big' },
      isSaved(chat) ? 'Saved Messages: a private place for notes, end-to-end encrypted.' : 'No messages here yet…')));
  }
  box.replaceChildren(...out);
  if (mode === 'bottom' || (mode !== 'prepend' && atBottom)) box.scrollTop = box.scrollHeight;
  else if (mode === 'prepend') box.scrollTop = box.scrollHeight - prevHeight + prevTop;
  else box.scrollTop = prevTop;
}

// ---------- attachments ----------

const blobs = new Map(); // file id -> Promise<object URL> of the decrypted file

const blobType = (f) => (INLINE_IMAGE.test(f.type) || MEDIA.test(f.type) ? f.type : 'application/octet-stream');

async function loadBlob(f) {
  const data = await download(`/api/files/${f.id}`);
  return new Blob([await cx.decryptFile(data, f.key, f.iv)], { type: blobType(f) });
}

/** A cached object URL for an image or voice message. */
function fileUrl(f) {
  let p = blobs.get(f.id);
  if (!p) {
    p = loadBlob(f).then((b) => URL.createObjectURL(b));
    p.catch(() => blobs.delete(f.id));
    blobs.set(f.id, p);
  }
  return p;
}

async function saveFile(f, iconSlot) {
  iconSlot?.replaceChildren(h('span', { class: 'spinner' }));
  try {
    const cached = blobs.get(f.id);
    const url = cached ? await cached : URL.createObjectURL(await loadBlob(f));
    const a = h('a', { href: url, download: f.name });
    document.body.append(a);
    a.click();
    a.remove();
    if (!cached) setTimeout(() => URL.revokeObjectURL(url), 60_000);
  } catch (e) {
    toast(`Download failed: ${e.message}`);
  } finally {
    iconSlot?.replaceChildren(icon('download'));
  }
}

function attachmentView(f, m) {
  if (f.voice) return voicePlayer(f, m);
  if (isImage(f)) return photoView(f, m);
  return fileCard(f, m);
}

const progressLabel = (p) => `${p.file.voice || isImage(p.file) ? '' : 'Uploading… '}${Math.round((p.progress || 0) * 100)}%`;

function setProgress(p, fraction) {
  p.progress = fraction;
  if (p.progressEl) p.progressEl.textContent = progressLabel(p);
}

function photoView(f, m) {
  const s = Math.min(1, 320 / f.w, 360 / f.h);
  const img = h('img', { class: 'photo', width: Math.max(60, Math.round(f.w * s)), height: Math.max(60, Math.round(f.h * s)), alt: '', draggable: 'false' });
  const box = h('div', { class: 'media' }, img);
  if (m.pending) {
    img.src = m.local;
    m.progressEl = h('span', { class: 'media-badge' }, progressLabel(m));
    box.append(m.progressEl);
    return box;
  }
  const show = () => {
    box.classList.add('loading');
    fileUrl(f).then((url) => { img.src = url; box.classList.remove('loading'); },
      () => box.replaceChildren(h('div', { class: 'media-error' }, icon('lock', 'inline'), ' Photo unavailable')));
  };
  if (f.size > MAX_AUTOLOAD && !blobs.has(f.id)) {
    const btn = h('button', { class: 'media-badge load', onclick: () => { btn.remove(); show(); } }, icon('download', 'inline'), ` ${fmtSize(f.size)}`);
    box.append(btn);
  } else {
    show();
  }
  img.addEventListener('click', () => fileUrl(f).then((url) => viewPhoto(url, f)));
  return box;
}

function fileCard(f, m) {
  const slot = h('span', { class: 'file-icon' }, icon(m.pending ? 'file' : 'download'));
  const sub = h('div', { class: 'file-size' }, fmtSize(f.size));
  if (m.pending) {
    m.progressEl = sub;
    sub.textContent = progressLabel(m);
  }
  return h(m.pending ? 'div' : 'button', {
    class: 'file-card', title: m.pending ? null : `Download ${f.name}`,
    onclick: m.pending ? null : () => saveFile(f, slot),
  }, slot, h('div', { class: 'file-info' }, h('div', { class: 'file-name' }, f.name), sub));
}

function viewPhoto(url, f) {
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  const close = () => { wrap.remove(); document.removeEventListener('keydown', onKey); };
  const wrap = h('div', { class: 'viewer', onclick: (e) => { if (e.target === wrap) close(); } },
    h('div', { class: 'viewer-bar' },
      h('span', { class: 'grow' }, f.name),
      h('button', { class: 'icon-btn', title: 'Download', onclick: () => saveFile(f) }, icon('download')),
      h('button', { class: 'icon-btn', title: 'Close', onclick: close }, icon('close'))),
    h('img', { class: 'viewer-img', src: url, alt: f.name }));
  document.addEventListener('keydown', onKey);
  document.body.append(wrap);
}

// One voice message plays at a time. Messages are re-rendered often, so the
// player looks up its current DOM in voiceEls instead of holding on to it.
let voice = null; // { id, audio, loading }
const voiceEls = new Map(); // file id -> { btn, fill, time, dur }

function voicePlayer(f, m) {
  const btn = h('button', { class: 'voice-btn', title: 'Play' }, icon('play'));
  const fill = h('div', { class: 'voice-fill' });
  const bar = h('div', { class: 'voice-bar' }, fill);
  const time = h('span', { class: 'voice-time' }, fmtDur(f.dur));
  const el = h('div', { class: 'voice' }, btn, h('div', { class: 'voice-body' }, bar, time));
  if (m.pending) {
    btn.disabled = true;
    m.progressEl = time;
    time.textContent = progressLabel(m);
    return el;
  }
  voiceEls.set(f.id, { btn, fill, time, dur: f.dur });
  btn.addEventListener('click', () => toggleVoice(f));
  bar.addEventListener('click', (e) => {
    if (voice?.id !== f.id || voice.loading) return;
    const r = bar.getBoundingClientRect();
    voice.audio.currentTime = Math.max(0, (e.clientX - r.left) / r.width) * f.dur;
  });
  if (voice?.id === f.id) syncVoice();
  return el;
}

async function toggleVoice(f) {
  if (voice?.id === f.id) {
    if (!voice.loading) { if (voice.audio.paused) voice.audio.play(); else voice.audio.pause(); }
    return;
  }
  stopVoice();
  const audio = new Audio();
  voice = { id: f.id, audio, loading: true };
  syncVoice();
  for (const ev of ['play', 'pause', 'timeupdate']) audio.addEventListener(ev, syncVoice);
  audio.addEventListener('ended', stopVoice);
  try {
    audio.src = await fileUrl(f);
    if (voice?.audio !== audio) return;
    voice.loading = false;
    await audio.play();
  } catch (e) {
    if (voice?.audio !== audio) return;
    stopVoice();
    toast(`Cannot play voice message: ${e.message}`);
  }
}

function stopVoice() {
  if (!voice) return;
  const { id, audio } = voice;
  voice = null;
  audio.pause();
  const v = voiceEls.get(id);
  if (v) {
    v.btn.replaceChildren(icon('play'));
    v.fill.style.width = '0';
    v.time.textContent = fmtDur(v.dur);
  }
}

function syncVoice() {
  const v = voice && voiceEls.get(voice.id);
  if (!v) return;
  const playing = !voice.loading && !voice.audio.paused;
  v.btn.replaceChildren(voice.loading ? h('span', { class: 'spinner' }) : icon(playing ? 'pause' : 'play'));
  v.btn.title = playing ? 'Pause' : 'Play';
  const t = voice.audio.currentTime || 0;
  v.fill.style.width = `${Math.min(100, (t / (v.dur || 1)) * 100)}%`;
  v.time.textContent = fmtDur(t);
}

const MAX_VOICE_MS = 10 * 60_000;

async function startRecording() {
  if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined') {
    toast('Voice messages need a browser with microphone support over HTTPS');
    return;
  }
  const chatId = state.openId;
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch {
    toast('Microphone access was denied');
    return;
  }
  if (state.openId !== chatId || state.recording) { stream.getTracks().forEach((t) => t.stop()); return; }
  const mimeType = ['audio/webm;codecs=opus', 'audio/ogg;codecs=opus', 'audio/mp4'].find((t) => MediaRecorder.isTypeSupported(t));
  const rec = new MediaRecorder(stream, mimeType ? { mimeType } : undefined);
  const r = { rec, stream, chunks: [], started: Date.now(), chatId };
  rec.ondataavailable = (e) => { if (e.data.size) r.chunks.push(e.data); };
  r.timer = setInterval(() => {
    const ms = Date.now() - r.started;
    els.recTime.textContent = fmtDur(Math.floor(ms / 1000));
    if (ms >= MAX_VOICE_MS) stopRecording(true);
  }, 250);
  rec.start();
  state.recording = r;
  els.recTime.textContent = '0:00';
  updateComposer();
}

function stopRecording(sendIt) {
  const r = state.recording;
  if (!r) return;
  state.recording = null;
  clearInterval(r.timer);
  const dur = (Date.now() - r.started) / 1000;
  r.rec.onstop = () => {
    r.stream.getTracks().forEach((t) => t.stop());
    const chat = state.chats.get(r.chatId);
    if (!sendIt || !chat || dur < 0.5) return;
    const type = (r.rec.mimeType || 'audio/webm').split(';')[0];
    sendFile(chat, new Blob(r.chunks, { type }), { name: `voice.${type.split('/')[1]}`, voice: { voice: true, dur } });
  };
  r.rec.stop();
  updateComposer();
}

async function imageSize(blob) {
  try {
    const b = await createImageBitmap(blob);
    const size = { w: b.width, h: b.height };
    b.close();
    return size;
  } catch {
    return {}; // not decodable: send it as a plain file
  }
}

function attachModal(files) {
  const chat = state.chats.get(state.openId);
  if (!chat) return;
  const caption = h('input', {
    class: 'field', placeholder: 'Add a caption…', maxlength: 4096, value: els.input.value.trim(),
    onkeydown: (e) => { if (e.key === 'Enter' && !e.isComposing) { e.preventDefault(); submit(); } },
  });
  const urls = [];
  const previews = files.map((f) => {
    if (INLINE_IMAGE.test(f.type)) {
      const u = URL.createObjectURL(f);
      urls.push(u);
      return h('img', { class: 'attach-thumb', src: u, alt: '' });
    }
    return h('div', { class: 'file-card' }, h('span', { class: 'file-icon' }, icon('file')),
      h('div', { class: 'file-info' }, h('div', { class: 'file-name' }, f.name), h('div', { class: 'file-size' }, fmtSize(f.size))));
  });
  const m = modal(files.length === 1 ? 'Send file' : `Send ${files.length} files`,
    h('div', { class: 'attach-list' }, previews), caption,
    h('div', { class: 'modal-actions' },
      h('button', { class: 'btn', onclick: () => m.close() }, 'Cancel'),
      h('button', { class: 'btn primary', onclick: submit }, 'Send')));
  m.onclose = () => urls.forEach((u) => URL.revokeObjectURL(u));

  async function submit() {
    const text = caption.value.trim();
    m.close();
    if (text && text === els.input.value.trim()) { els.input.value = ''; autosize(); updateComposer(); }
    for (const [i, f] of files.entries()) await sendFile(chat, f, { name: f.name || 'file', caption: i === 0 ? text : '' });
  }
}

// ---------- sending & editing ----------

function pendingItem(text, file = null) {
  return { clientId: crypto.randomUUID(), text, file, createdAt: Date.now(), senderId: state.me.id, kind: 'msg', pending: true };
}

function failed(p, e) {
  p.failed = true;
  toast(`Message not sent: ${e.message}`);
  render();
}

async function send() {
  const text = els.input.value.trim();
  const chat = state.chats.get(state.openId);
  if (!text || !chat) return;
  els.input.value = '';
  autosize();
  updateComposer();
  const p = pendingItem(text);
  chat.pending.push(p);
  renderMessages('bottom');
  await deliver(chat, p, toPayload(text));
}

/** Encrypts the file, uploads it and sends a message that carries its key. */
async function sendFile(chat, blob, { name, caption = '', voice: voiceMeta = null }) {
  if (state.maxUpload && blob.size + 16 > state.maxUpload) {
    toast(`${name} is too large (the limit is ${fmtSize(state.maxUpload)})`);
    return;
  }
  const file = { name, type: blob.type || '', size: blob.size, ...voiceMeta };
  if (!voiceMeta && INLINE_IMAGE.test(file.type)) Object.assign(file, await imageSize(blob));
  const p = pendingItem(caption, file);
  if (voiceMeta || isImage(file)) p.local = URL.createObjectURL(blob);
  chat.pending.push(p);
  if (state.openId === chat.id) renderMessages('bottom');
  try {
    const enc = await cx.encryptFile(new Uint8Array(await blob.arrayBuffer()));
    const { file: up } = await upload('POST', `/api/chats/${chat.id}/files`, enc.data, (f) => setProgress(p, f));
    if (p.local) blobs.set(up.id, Promise.resolve(p.local));
    await deliver(chat, p, toPayload(caption, { ...file, id: up.id, key: enc.key, iv: enc.iv }), [up.id]);
  } catch (e) {
    failed(p, e);
  }
}

// deliver encrypts and posts a message, retrying once if the group key
// changed under us.
async function deliver(chat, p, payload, fileIds = []) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const epoch = chat.kind === 'group' ? chat.keyEpoch : 0;
      await ensureGroupKey(chat);
      const key = await getKey(chat, epoch);
      if (!key) throw new Error('No encryption key for this chat yet');
      const { ciphertext, iv } = await cx.encryptMessage(key, payload, cx.messageAAD(chat.id, state.me.id, epoch));
      const { message } = await api('POST', `/api/chats/${chat.id}/messages`, { ciphertext, iv, epoch, clientId: p.clientId, fileIds });
      state.plain.set(message.id, toPlain(payload));
      addMessage(chat, message);
      render();
      return;
    } catch (e) {
      if (e.status === 409 && attempt === 0) {
        await refreshChat(chat.id); // key epoch changed under us
        continue;
      }
      failed(p, e);
      return;
    }
  }
}

let editing = null; // { chatId, m } while the composer edits a message

function canEdit(m) {
  if (m.kind !== 'msg' || m.senderId !== state.me.id || m.pending || !m.id) return false;
  const p = state.plain.get(m.id);
  return !!p && !p.error && !p.file?.voice;
}

function startEdit(chat, m) {
  const p = plainOf(m);
  editing = { chatId: chat.id, m };
  els.editText.textContent = describe(p);
  els.input.value = p.text;
  autosize();
  updateComposer();
  els.input.focus();
  els.input.setSelectionRange(p.text.length, p.text.length);
}

function cancelEdit() {
  if (!editing) return;
  editing = null;
  els.input.value = '';
  autosize();
  updateComposer();
}

// Edits re-encrypt the whole payload (attachment included) under the
// message's original epoch, so exactly the same members can read it.
async function saveEdit() {
  const { chatId, m } = editing;
  const chat = state.chats.get(chatId);
  const old = plainOf(m);
  const text = els.input.value.trim();
  if (!text && !old.file) { toast('A message cannot be empty'); return; }
  cancelEdit();
  if (!chat || text === old.text) return;
  const payload = toPayload(text, old.file);
  try {
    const key = await getKey(chat, m.epoch);
    if (!key) throw new Error('No encryption key for this message');
    const { ciphertext, iv } = await cx.encryptMessage(key, payload, cx.messageAAD(chat.id, state.me.id, m.epoch));
    const { message } = await api('PATCH', `/api/chats/${chat.id}/messages/${m.id}`, { ciphertext, iv });
    state.plain.set(message.id, toPlain(payload));
    applyEdit(chat, message);
    render();
  } catch (e) {
    toast(`Edit failed: ${e.message}`);
  }
}

function applyEdit(chat, m) {
  for (const x of [chat.messages?.find((y) => y.id === m.id), chat.lastMessage]) {
    if (x?.id === m.id) Object.assign(x, m);
  }
}

function messageMenu(e, chat, m) {
  if (m.pending || m.kind !== 'msg' || getSelection()?.toString()) return; // keep the native menu for selections
  const p = plainOf(m);
  const items = [];
  if (canEdit(m)) items.push(['edit', 'Edit', () => startEdit(chat, m)]);
  if (p.text) items.push(['copy', 'Copy Text', () => copy(p.text, 'Text copied')]);
  if (p.file && !p.file.voice) items.push(['download', 'Download', () => saveFile(p.file)]);
  if (!items.length) return;
  e.preventDefault();
  const close = () => { scrim.remove(); menu.remove(); };
  const scrim = h('div', { class: 'menu-scrim', onclick: close, oncontextmenu: (ev) => { ev.preventDefault(); close(); } });
  const menu = h('div', { class: 'menu', role: 'menu' }, items.map(([ic, label, fn]) =>
    h('button', { class: 'menu-item', role: 'menuitem', onclick: () => { close(); fn(); } }, icon(ic), label)));
  document.body.append(scrim, menu);
  const r = menu.getBoundingClientRect();
  menu.style.left = `${Math.max(8, Math.min(e.clientX, innerWidth - r.width - 8))}px`;
  menu.style.top = `${Math.max(8, Math.min(e.clientY, innerHeight - r.height - 8))}px`;
}

// ---------- drawer & modals ----------

function openDrawer() {
  const close = () => { scrim.remove(); drawer.remove(); };
  const item = (ic, label, fn) => h('button', { class: 'drawer-item', onclick: () => { close(); fn(); } }, icon(ic), label);
  const dark = document.documentElement.dataset.theme === 'dark';
  const scrim = h('div', { class: 'scrim', onclick: close });
  const drawer = h('nav', { class: 'drawer' },
    h('button', { class: 'drawer-head', title: 'Edit profile', onclick: () => { close(); profileModal(); } },
      avatar(state.me.id, state.me.displayName, 'lg'),
      h('div', { class: 'drawer-name' }, state.me.displayName),
      h('div', { class: 'drawer-user' }, `@${state.me.username}`)),
    item('person', 'My Profile', profileModal),
    item('group', 'New Group', newGroupModal),
    item('bookmark', 'Saved Messages', () => startDirect(state.me.id)),
    state.canInvite ? item('link', 'Invite Friends', inviteModal) : null,
    item('moon', dark ? 'Day Mode' : 'Night Mode', () => setTheme(dark ? 'light' : 'dark')),
    item('logout', 'Log Out', () => logout(true)),
    h('div', { class: 'drawer-foot' }, icon('lock', 'inline'), ' emerchat · end-to-end encrypted'));
  document.body.append(scrim, drawer);
}

function modal(title, ...body) {
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  const close = () => {
    if (!wrap.isConnected) return;
    wrap.remove();
    document.removeEventListener('keydown', onKey);
    m.onclose?.();
  };
  const wrap = h('div', { class: 'modal-wrap', onclick: (e) => { if (e.target === wrap) close(); } },
    h('div', { class: 'modal', role: 'dialog', 'aria-label': title },
      h('div', { class: 'modal-head' },
        h('span', { class: 'modal-title' }, title),
        h('button', { class: 'icon-btn', title: 'Close', onclick: close }, icon('close'))),
      h('div', { class: 'modal-body' }, ...body)));
  document.addEventListener('keydown', onKey);
  document.body.append(wrap);
  wrap.querySelector('input:not([readonly]):not([type=file])')?.focus();
  const m = { wrap, close, onclose: null };
  return m;
}

function userPicker(onPick, exclude = new Set()) {
  const input = h('input', { class: 'field', placeholder: 'Search people by name or @username', autocomplete: 'off' });
  const results = h('div', { class: 'picker-results' });
  let t;
  input.addEventListener('input', () => {
    clearTimeout(t);
    t = setTimeout(async () => {
      const q = input.value.trim();
      if (!q) { results.replaceChildren(); return; }
      const { users } = await api('GET', `/api/users?q=${encodeURIComponent(q)}`);
      rememberUsers(users);
      results.replaceChildren(...users.filter((u) => !exclude.has(u.id)).map((u) =>
        h('button', { class: 'person', onclick: () => { onPick(u); input.value = ''; results.replaceChildren(); input.focus(); } },
          avatar(u.id, u.displayName, 'sm'),
          h('div', {}, h('div', { class: 'person-name' }, u.displayName), h('div', { class: 'muted' }, `@${u.username}`)))));
    }, 200);
  });
  return h('div', { class: 'picker' }, input, results);
}

function newGroupModal() {
  const selected = new Map();
  const chips = h('div', { class: 'chips' });
  const title = h('input', { class: 'field', placeholder: 'Group name', maxlength: 128 });
  const create = h('button', { class: 'btn primary', onclick: submit }, 'Create');
  const renderChips = () => chips.replaceChildren(...[...selected.values()].map((u) =>
    h('span', { class: 'chip' }, avatar(u.id, u.displayName, 'xs'), u.displayName,
      h('button', { class: 'chip-x', title: 'Remove', onclick: () => { selected.delete(u.id); renderChips(); } }, icon('close')))));
  const m = modal('New Group', title, chips,
    userPicker((u) => { selected.set(u.id, u); renderChips(); }, new Set([state.me.id])),
    h('div', { class: 'modal-actions' }, create));

  async function submit() {
    if (!title.value.trim()) { title.focus(); return; }
    create.disabled = true;
    try {
      const raw = cx.newGroupKey();
      const members = [state.me, ...selected.values()];
      const keys = await wrapForMembers(raw, 0, members);
      const { chat } = await api('POST', '/api/chats', { title: title.value.trim(), memberIds: [...selected.keys()], keys });
      state.keys.set(chat.id, new Map([[0, { raw, key: await cx.importGroupKey(raw) }]]));
      adoptChat(chat);
      m.close();
      location.hash = `#/c/${chat.id}`;
    } catch (e) {
      toast(e.message);
      create.disabled = false;
    }
  }
}

async function chatInfoModal(chat) {
  if (chat.kind === 'direct') {
    const peer = peerOf(chat);
    const body = [h('div', { class: 'profile' },
      isSaved(chat) ? avatar(0, '', 'xl', 'saved') : avatar(peer.id, peer.displayName, 'xl'),
      h('div', { class: 'profile-name' }, chatTitle(chat)),
      h('div', { class: 'muted' }, isSaved(chat) ? 'Notes only you can read' : `@${peer.username} · ${lastSeen(peer)}`))];
    if (!isSaved(chat)) {
      const groups = await cx.safetyNumber(state.me.publicKey, peer.publicKey);
      body.push(h('div', { class: 'section' },
        h('div', { class: 'section-title' }, icon('lock', 'inline'), ' Encryption'),
        h('div', { class: 'safety' }, groups.map((g) => h('span', {}, g))),
        h('p', { class: 'muted small' },
          `Compare these numbers with ${peer.displayName} in person or over a trusted channel. `,
          'If they match, nobody (including the server) can read your messages.')));
    }
    modal('Info', ...body);
    return;
  }

  const me = myMember(chat);
  const isOwner = me?.role === 'owner';
  const list = h('div', { class: 'members' });
  const subtitle = h('div', { class: 'muted' });
  const renderMembers = () => {
    subtitle.textContent = `${chat.members.length} members · key epoch ${chat.keyEpoch}`;
    list.replaceChildren(...chat.members.map((u) =>
    h('div', { class: 'person' },
      avatar(u.id, u.displayName, 'sm'),
      h('div', { class: 'grow' },
        h('div', { class: 'person-name' }, u.id === state.me.id ? `${u.displayName} (you)` : u.displayName),
        h('div', { class: 'muted' }, u.role === 'owner' ? 'owner' : lastSeen(u))),
      isOwner && u.id !== state.me.id
        ? h('button', { class: 'icon-btn danger', title: 'Remove from group', onclick: () => removeMember(u) }, icon('trash'))
        : null)));
  };
  renderMembers();

  const linkBox = h('div');
  const renderLink = () => {
    if (!chat.inviteCode) {
      linkBox.replaceChildren(h('button', { class: 'btn primary', onclick: createLink }, icon('link', 'inline'), ' Create invite link'));
      return;
    }
    const link = groupLink(chat.inviteCode);
    linkBox.replaceChildren(h('div', { class: 'invite' },
      h('div', { class: 'grow' },
        h('input', { class: 'invite-link', readonly: true, value: link, onfocus: (e) => e.target.select() }),
        h('div', { class: 'muted small' }, 'Anyone with this link can join. It does not expire.')),
      h('button', { class: 'icon-btn', title: 'Copy', onclick: () => copy(link) }, icon('copy')),
      isOwner ? h('button', { class: 'icon-btn danger', title: 'Revoke link', onclick: revokeLink }, icon('trash')) : null));
  };
  renderLink();

  // Group photo and name; any member can change them.
  const pic = h('div', { class: 'profile-pic' });
  const picker = h('input', { type: 'file', accept: 'image/*', hidden: true, onchange: () => {
    const f = picker.files[0];
    picker.value = '';
    if (f) setPhoto(f);
  } });
  const removePhotoBtn = h('button', { class: 'btn danger', onclick: removePhoto }, 'Remove photo');
  const nameRow = h('div', { class: 'name-row' });
  const renderProfile = () => {
    pic.replaceChildren(chatAvatar(chat, 'xl'),
      h('button', { class: 'pic-btn', title: 'Change group photo', onclick: () => picker.click() }, icon('camera')));
    removePhotoBtn.hidden = !chat.photo;
    nameRow.replaceChildren(h('div', { class: 'profile-name' }, chat.title),
      h('button', { class: 'icon-btn', title: 'Rename group', onclick: editTitle }, icon('edit')));
  };
  renderProfile();

  const m = modal('Group Info',
    h('div', { class: 'profile' }, pic, nameRow, subtitle, removePhotoBtn, picker),
    h('div', { class: 'section' }, h('div', { class: 'section-title' }, icon('link', 'inline'), ' Invite link'), linkBox),
    h('div', { class: 'section' }, h('div', { class: 'section-title' }, icon('personAdd', 'inline'), ' Add member'),
      userPicker(addMember, { has: (id) => chat.members.some((x) => x.id === id) })),
    h('div', { class: 'section' }, h('div', { class: 'section-title' }, 'Members'), list),
    h('div', { class: 'modal-actions' },
      h('button', { class: 'btn danger', onclick: leave }, icon('logout', 'inline'), ' Leave group')));

  async function addMember(u) {
    try {
      await ensureGroupKey(chat);
      const k = state.keys.get(chat.id)?.get(chat.keyEpoch);
      if (!k?.raw) throw new Error('Group key unavailable');
      const [wrapped] = await wrapForMembers(k.raw, chat.keyEpoch, [u]);
      await api('POST', `/api/chats/${chat.id}/members`, wrapped);
      await refreshChat(chat.id);
      renderMembers();
      toast(`${u.displayName} added`);
    } catch (e) {
      toast(e.message);
    }
  }

  function editTitle() {
    const input = h('input', { class: 'field', value: chat.title, maxlength: 128, placeholder: 'Group name',
      onkeydown: (e) => {
        if (e.key === 'Enter' && !e.isComposing) { e.preventDefault(); save(); }
        if (e.key === 'Escape') { e.stopPropagation(); renderProfile(); }
      } });
    const save = async () => {
      const title = input.value.trim();
      if (!title) { input.focus(); return; }
      if (title === chat.title) { renderProfile(); return; }
      try {
        const { chat: c } = await api('PATCH', `/api/chats/${chat.id}`, { title });
        adoptChat(c);
        renderProfile();
        render();
      } catch (e) {
        toast(e.message);
      }
    };
    nameRow.replaceChildren(h('div', { class: 'title-edit' }, input,
      h('button', { class: 'icon-btn', title: 'Cancel', onclick: renderProfile }, icon('close')),
      h('button', { class: 'icon-btn accent', title: 'Save', onclick: save }, icon('check'))));
    input.focus();
    input.select();
  }

  async function setPhoto(f) {
    try {
      const blob = await squareImage(f, 320);
      const { chat: c } = await upload('PUT', `/api/chats/${chat.id}/photo`, blob);
      adoptChat(c);
      renderProfile();
      render();
    } catch (e) {
      toast(e.message || 'Could not use that image');
    }
  }

  async function removePhoto() {
    try {
      const { chat: c } = await api('DELETE', `/api/chats/${chat.id}/photo`);
      adoptChat(c);
      renderProfile();
      render();
    } catch (e) {
      toast(e.message);
    }
  }

  async function createLink() {
    try {
      const { code } = await api('POST', `/api/chats/${chat.id}/link`, {});
      chat.inviteCode = code;
      renderLink();
    } catch (e) {
      toast(e.message);
    }
  }

  async function revokeLink() {
    if (!confirm('Revoke this invite link? It will stop working for everyone. You can create a new one afterwards.')) return;
    try {
      await api('DELETE', `/api/chats/${chat.id}/link`);
      chat.inviteCode = '';
      renderLink();
    } catch (e) {
      toast(e.message);
    }
  }

  async function removeMember(u) {
    if (!confirm(`Remove ${u.displayName} from ${chat.title}? A new group key will be created.`)) return;
    try {
      await api('DELETE', `/api/chats/${chat.id}/members/${u.id}`);
      await refreshChat(chat.id); // picks up the new epoch and rekeys
      renderMembers();
    } catch (e) {
      toast(e.message);
    }
  }

  async function leave() {
    if (!confirm(`Leave ${chat.title}?`)) return;
    try {
      chat.leaving = true;
      await api('DELETE', `/api/chats/${chat.id}/members/${state.me.id}`);
      m.close();
      dropChat(chat.id);
    } catch (e) {
      chat.leaving = false;
      toast(e.message);
    }
  }
}

async function inviteModal() {
  const list = h('div', { class: 'invites' });
  const create = h('button', { class: 'btn primary', onclick: async () => {
    create.disabled = true;
    try { await api('POST', '/api/invites', {}); await refresh(); } catch (e) { toast(e.message); }
    create.disabled = false;
  } }, icon('link', 'inline'), ' Create invite link');
  modal('Invite Friends',
    h('p', { class: 'muted small' }, 'emerchat is invite-only. Each link works once and expires after 7 days.'),
    create, list);

  async function refresh() {
    const { invites } = await api('GET', '/api/invites');
    const now = Date.now();
    list.replaceChildren(...invites.map((inv) => {
      const link = `${location.origin}${location.pathname}#/join/${inv.code}`;
      let status, active = false;
      if (inv.usedBy) status = `Used by ${inv.usedBy.displayName} (@${inv.usedBy.username})`;
      else if (inv.expiresAt <= now) status = 'Expired';
      else { active = true; status = `Active · expires ${shortDate(inv.expiresAt)}`; }
      return h('div', { class: `invite${active ? '' : ' inactive'}` },
        h('div', { class: 'grow' },
          h('input', { class: 'invite-link', readonly: true, value: link, onfocus: (e) => e.target.select() }),
          h('div', { class: 'muted small' }, status)),
        active ? h('button', { class: 'icon-btn', title: 'Copy', onclick: () => copy(link) }, icon('copy')) : null,
        active ? h('button', { class: 'icon-btn danger', title: 'Revoke', onclick: async () => {
          await api('DELETE', `/api/invites/${encodeURIComponent(inv.code)}`).catch((e) => toast(e.message));
          refresh();
        } }, icon('trash')) : null);
    }));
    if (!invites.length) list.replaceChildren(h('div', { class: 'muted small center' }, 'No invites yet'));
  }
  refresh().catch((e) => toast(e.message));
}

const groupLink = (code) => `${location.origin}${location.pathname}#/g/${code}`;

async function joinLinkModal(code) {
  let preview;
  try {
    preview = await api('GET', `/api/join/${encodeURIComponent(code)}`);
  } catch (e) {
    toast(e.status === 404 ? 'This invite link is invalid or was revoked' : e.message);
    return;
  }
  const existing = [...state.chats.values()].find((c) => c.inviteCode === code);
  if (existing) { location.hash = `#/c/${existing.id}`; return; }
  const g = preview.group;
  const join = h('button', { class: 'btn primary wide', onclick: async () => {
    join.disabled = true;
    try {
      await joinGroup(code);
      m.close();
    } catch (e) {
      toast(e.message);
      join.disabled = false;
    }
  } }, 'Join group');
  const m = modal('Invitation',
    h('div', { class: 'profile' }, avatar(-1, g.title, 'xl'),
      h('div', { class: 'profile-name' }, g.title),
      h('div', { class: 'muted' }, `${g.members} member${g.members === 1 ? '' : 's'}`)),
    h('p', { class: 'muted small center' }, 'You will be able to read messages sent after you join.'),
    join);
}

async function joinGroup(code) {
  const { chat: c } = await api('POST', `/api/join/${encodeURIComponent(code)}`);
  const chat = adoptChat(c);
  location.hash = `#/c/${chat.id}`;
}

function profileModal() {
  const me = state.me;
  const pic = h('div', { class: 'profile-pic' });
  const picker = h('input', { type: 'file', accept: 'image/*', hidden: true, onchange: () => {
    const f = picker.files[0];
    picker.value = '';
    if (f) setPhoto(f);
  } });
  const removeBtn = h('button', { class: 'btn danger', onclick: removePhoto }, 'Remove photo');
  const renderPic = () => {
    pic.replaceChildren(avatar(me.id, me.displayName, 'xl'),
      h('button', { class: 'pic-btn', title: 'Change photo', onclick: () => picker.click() }, icon('camera')));
    removeBtn.hidden = !me.avatar;
  };
  renderPic();
  const name = h('input', { class: 'field', value: me.displayName, maxlength: 64, placeholder: 'Your name',
    onkeydown: (e) => { if (e.key === 'Enter') save(); } });
  const saveBtn = h('button', { class: 'btn primary', onclick: save }, 'Save');
  const m = modal('Edit Profile',
    h('div', { class: 'profile' }, pic, h('div', { class: 'muted' }, `@${me.username}`), removeBtn, picker),
    h('div', { class: 'section' }, h('div', { class: 'section-title' }, 'Your name'), name),
    h('div', { class: 'modal-actions' }, saveBtn));

  async function setPhoto(f) {
    try {
      const blob = await squareImage(f, 320);
      const { user } = await upload('PUT', '/api/me/avatar', blob);
      applyUser(user);
      renderPic();
      render();
    } catch (e) {
      toast(e.message || 'Could not use that image');
    }
  }

  async function removePhoto() {
    try {
      const { user } = await api('DELETE', '/api/me/avatar');
      applyUser(user);
      renderPic();
      render();
    } catch (e) {
      toast(e.message);
    }
  }

  async function save() {
    const v = name.value.trim();
    if (!v) { name.focus(); return; }
    if (v === me.displayName) { m.close(); return; }
    saveBtn.disabled = true;
    try {
      const { user } = await api('PATCH', '/api/me', { displayName: v });
      applyUser(user);
      render();
      m.close();
    } catch (e) {
      toast(e.message);
      saveBtn.disabled = false;
    }
  }
}

/** Center-crops an image to a size×size JPEG. */
async function squareImage(file, size) {
  let bmp;
  try { bmp = await createImageBitmap(file); } catch { throw new Error('That file is not an image this browser can read'); }
  const s = Math.min(bmp.width, bmp.height);
  const canvas = document.createElement('canvas');
  canvas.width = canvas.height = size;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#fff'; // transparent PNGs would turn black in JPEG
  ctx.fillRect(0, 0, size, size);
  ctx.drawImage(bmp, (bmp.width - s) / 2, (bmp.height - s) / 2, s, s, 0, 0, size, size);
  bmp.close();
  return new Promise((resolve, reject) => canvas.toBlob((b) => (b ? resolve(b) : reject(new Error('Could not encode image'))), 'image/jpeg', 0.88));
}

async function copy(text, done = 'Link copied') {
  try { await navigator.clipboard.writeText(text); toast(done); } catch { toast('Copying failed; select the text and copy it manually'); }
}

// ---------- theme ----------

function setTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem('theme', t); } catch { /* private mode */ }
}

function initTheme() {
  let t = null;
  try { t = localStorage.getItem('theme'); } catch { /* private mode */ }
  if (!t) t = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.dataset.theme = t;
}

// ---------- auth screens ----------

// link is { invite } for a personal invite or { group } for a group's invite
// link; the latter also works for people who already have an account.
async function authScreen(mode, link = {}) {
  let group = null, notice = '';
  if (link.group) {
    try {
      const p = await api('GET', `/api/join/${encodeURIComponent(link.group)}`);
      group = { code: link.group, title: p.group.title, canSignUp: p.canSignUp };
      if (!group.canSignUp) mode = 'login';
    } catch (e) {
      notice = e.status === 404 ? 'This invite link is invalid or was revoked.' : e.message;
      mode = 'login';
    }
  }
  const err = h('div', { class: 'auth-error' }, notice);
  const busy = h('div', { class: 'auth-busy' });
  const username = h('input', { class: 'field', placeholder: 'Username', autocomplete: 'username', autocapitalize: 'off', spellcheck: 'false', required: true });
  const display = h('input', { class: 'field', placeholder: 'Your name', autocomplete: 'name', maxlength: 64 });
  const password = h('input', { class: 'field', type: 'password', placeholder: 'Password', autocomplete: mode === 'join' ? 'new-password' : 'current-password', required: true });
  const confirmPw = h('input', { class: 'field', type: 'password', placeholder: 'Repeat password', autocomplete: 'new-password' });
  const submit = h('button', { class: 'btn primary wide', type: 'submit' }, mode === 'join' ? 'Create account' : 'Log in');

  let intro;
  if (group && mode === 'join') intro = ['You are invited to join ', h('b', {}, group.title), '. Pick a username and password. Your password also protects your encryption key, so it cannot be recovered.'];
  else if (group) intro = ['Log in to join ', h('b', {}, group.title), '.', group.canSignUp ? null : ' New accounts need a personal invite.'];
  else if (mode === 'join') intro = 'You were invited! Pick a username and password. Your password also protects your encryption key, so it cannot be recovered.';
  else intro = 'Log in to continue. New here? You need an invite link.';

  const form = h('form', { class: 'auth-card', onsubmit: async (e) => {
    e.preventDefault();
    err.textContent = '';
    if (mode === 'join' && password.value !== confirmPw.value) { err.textContent = 'Passwords do not match'; return; }
    if (mode === 'join' && password.value.length < 8) { err.textContent = 'Use at least 8 characters'; return; }
    submit.disabled = true;
    busy.textContent = 'Deriving keys…';
    try {
      let r = null;
      if (mode === 'join') r = await register({ invite: link.invite, groupInvite: group?.code }, username.value, display.value, password.value);
      else await login(username.value, password.value);
      history.replaceState(null, '', location.pathname);
      await startApp();
      if (r?.chatId) location.hash = `#/c/${r.chatId}`;
      else if (group && state.running) await joinGroup(group.code).catch((e3) => toast(e3.message));
    } catch (e2) {
      err.textContent = e2.message;
      submit.disabled = false;
      busy.textContent = '';
    }
  } },
  h('div', { class: 'logo' }, icon('send')),
  h('h1', {}, 'emerchat'),
  h('p', { class: 'muted' }, intro),
  username,
  mode === 'join' ? display : null,
  password,
  mode === 'join' ? confirmPw : null,
  err, submit, busy,
  group?.canSignUp ? h('button', { class: 'btn wide auth-switch', type: 'button', onclick: () => authScreen(mode === 'join' ? 'login' : 'join', link) },
    mode === 'join' ? 'I already have an account' : 'Create a new account') : null);
  $root.replaceChildren(h('div', { class: 'auth' }, form));
  username.focus();
}

async function register({ invite, groupInvite }, username, displayName, password) {
  const kdfSalt = cx.b64(cx.randomBytes(16));
  const { authKey, wrapKey } = await cx.deriveLoginKeys(password, kdfSalt);
  const id = await cx.createIdentity(wrapKey);
  const r = await api('POST', '/api/register', {
    invite: invite || '', groupInvite: groupInvite || '', username, displayName, authKey, kdfSalt,
    publicKey: id.publicKey, wrappedPrivateKey: id.wrappedPrivateKey, wrapIv: id.wrapIv,
  });
  await saveKey(r.user.id, id.privateKey);
  state.privateKey = id.privateKey;
  return r;
}

async function login(username, password) {
  const { kdfSalt } = await api('GET', `/api/prelogin?u=${encodeURIComponent(username)}`);
  const { authKey, wrapKey } = await cx.deriveLoginKeys(password, kdfSalt);
  const r = await api('POST', '/api/login', { username, authKey });
  const pk = await cx.unwrapIdentity(wrapKey, r.wrappedPrivateKey, r.wrapIv);
  await saveKey(r.user.id, pk);
  state.privateKey = pk;
}

async function logout(callServer) {
  state.running = false;
  pollAbort?.abort();
  if (callServer) await api('POST', '/api/logout', {}).catch(() => {});
  await clearKeys();
  location.hash = '';
  location.reload();
}

// ---------- boot & routing ----------

async function startApp() {
  const me = await api('GET', '/api/me');
  state.me = me.user;
  state.canInvite = me.canInvite;
  state.maxUpload = me.maxUpload;
  rememberUsers([me.user]);
  state.privateKey ||= await loadKey(me.user.id);
  if (!state.privateKey) {
    // Session is valid but this browser lost the key: ask for the password again.
    authScreen('login', { group: hashLink('g') });
    return;
  }
  buildShell();
  await loadChats();
  state.running = true;
  pollLoop();
  route();
}

const hashLink = (kind) => location.hash.match(new RegExp(`^#/${kind}/([\\w-]+)$`))?.[1];

function route() {
  const m = location.hash.match(/^#\/c\/(\d+)$/);
  if (!state.running) {
    const invite = hashLink('join'), group = hashLink('g');
    if ((invite || group) && !state.me) authScreen('join', { invite, group });
    return;
  }
  const group = hashLink('g');
  if (group) {
    history.replaceState(null, '', location.pathname);
    joinLinkModal(group);
    return;
  }
  if (m) {
    const id = Number(m[1]);
    if (id !== state.openId) openChat(id);
  } else if (state.openId) {
    closeChat();
  }
}

async function boot() {
  initTheme();
  window.addEventListener('hashchange', route);
  window.addEventListener('online', () => wakeSleep?.());
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') { wakeSleep?.(); scheduleRead(); render(); }
  });
  setInterval(() => { if (state.openId) renderHeader(); }, 60_000); // refresh "last seen"

  const join = hashLink('join'), group = hashLink('g');
  try {
    if (join) {
      // An invite link while logged in: just open the app.
      await api('GET', '/api/me');
      history.replaceState(null, '', location.pathname);
    }
    await startApp();
  } catch (e) {
    if (e.status === 401) authScreen(join || group ? 'join' : 'login', { invite: join, group });
    else $root.replaceChildren(h('div', { class: 'auth' }, h('div', { class: 'auth-card' },
      h('h1', {}, 'Cannot reach server'), h('p', { class: 'muted' }, e.message),
      h('button', { class: 'btn primary wide', onclick: () => location.reload() }, 'Retry'))));
  }
}

boot();
