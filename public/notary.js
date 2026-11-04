// The Notary, in the browser: render the archive, the row as stored, the master key and the wire.
// Visitors write deed titles, so everything goes through textContent, never innerHTML.
const $ = (id) => document.getElementById(id);
const SVG = 'http://www.w3.org/2000/svg';
let current = { deeds: [], key: null, selected: null, row: null };
let busy = false;

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) node.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined) node.append(c);
  return node;
}

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, { method, headers: body ? { 'content-type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  let data = null;
  try { data = await res.json(); } catch { /* empty */ }
  if (!res.ok) throw Object.assign(new Error(data?.error || `HTTP ${res.status}`), { status: res.status, data });
  return data;
}

const when = (iso) => iso ? new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '';
const vBadge = (v, locked = false) => el('span', { class: `ver${locked ? ' is-locked' : ''}`, dataset: { v: String(((v - 1) % 3) + 1 || 0) } }, `${locked ? '🔒 ' : ''}v${v}`);

function waxSeal(v, locked) {
  const colors = ['#fcb900', '#b7b5ff', '#5fe3d3'];
  const s = document.createElementNS(SVG, 'svg');
  s.setAttribute('viewBox', '0 0 34 34');
  s.setAttribute('class', 'deed__seal');
  s.setAttribute('aria-hidden', 'true');
  const ring = document.createElementNS(SVG, 'path');
  ring.setAttribute('d', 'M17 2l3.1 2.6 4-.6 1.6 3.7 3.7 1.6-.6 4L31.4 17l-2.6 3.1.6 4-3.7 1.6-1.6 3.7-4-.6L17 31.4l-3.1-2.6-4 .6-1.6-3.7-3.7-1.6.6-4L2.6 17l2.6-3.1-.6-4 3.7-1.6L9.9 4.6l4 .6z');
  ring.setAttribute('fill', locked ? '#3a2030' : '#a51050');
  const inner = document.createElementNS(SVG, 'circle');
  inner.setAttribute('cx', '17'); inner.setAttribute('cy', '17'); inner.setAttribute('r', '9');
  inner.setAttribute('fill', 'none'); inner.setAttribute('stroke', locked ? '#ff9aab' : colors[(v - 1) % 3] || '#f57461'); inner.setAttribute('stroke-width', '1.6');
  const t = document.createElementNS(SVG, 'text');
  t.setAttribute('x', '17'); t.setAttribute('y', '20.5'); t.setAttribute('text-anchor', 'middle');
  t.setAttribute('font-family', 'JetBrains Mono, monospace'); t.setAttribute('font-size', '9'); t.setAttribute('font-weight', '600');
  t.setAttribute('fill', '#fff'); t.textContent = `v${v}`;
  s.append(ring, inner, t);
  return s;
}

// ---------- The wire ----------
function jsonNode(value) {
  const pre = el('pre', { class: 'call__json' });
  const text = JSON.stringify(value, null, 2);
  // Colour the sealed keys, the redacted data keys and the errors; everything else stays plain text.
  const re = /"(vault:v\d+:[^"]*)"|"(‹[^"]*›)"|("errors": \[[^\]]*\])/g;
  let last = 0;
  for (const m of text.matchAll(re)) {
    pre.append(text.slice(last, m.index));
    const cls = m[1] ? 'is-sealed' : m[2] ? 'is-secret' : 'is-error';
    pre.append(el('span', { class: cls }, m[0]));
    last = m.index + m[0].length;
  }
  pre.append(text.slice(last));
  return pre;
}

const ECHOES = ['sealEcho', 'inspEcho', 'rotateEcho', 'resealEcho', 'lockEcho'];

// The same calls, one short line each, next to the button that made them (shown on narrow screens).
function renderEcho(id, calls, hidden) {
  for (const e of ECHOES) $(e).replaceChildren();
  if (!id) return;
  const shown = calls.slice(0, 3);
  const more = calls.length - shown.length + hidden;
  $(id).replaceChildren(...shown.map((c) => {
    const ok = c.status >= 200 && c.status < 300;
    return el('li', {}, el('b', {}, c.method), el('span', {}, c.path.replace(/^\/v1\//, '')), el('span', { class: ok ? 'ok' : 'ko' }, `→ ${c.status || '—'}`));
  }), ...(more > 0 ? [el('li', {}, `… ${more} more`)] : []));
}

function renderWire(story, calls = [], hidden = 0, echo = null) {
  renderEcho(echo, calls, hidden);
  $('wireStory').replaceChildren(...story);
  const refused = calls.some((c) => c.status >= 400 || c.status === 0);
  const lamp = $('wireLamp');
  lamp.className = `wire__lamp ${refused ? 'is-refused' : 'is-on'}`;
  setTimeout(() => { if (!refused) lamp.className = 'wire__lamp'; }, 1400);
  $('wireCalls').replaceChildren(...calls.map((c, i) => {
    const ok = c.status >= 200 && c.status < 300;
    return el('li', {},
      el('details', { class: 'call', style: `--i:${i}`, open: i === calls.length - 1 && calls.length <= 3 },
        el('summary', {},
          el('span', { class: 'call__method' }, c.method),
          el('span', { class: 'call__path' }, c.path),
          el('span', { class: 'call__ms' }, `${c.ms} ms`),
          el('span', { class: `call__status ${ok ? 'is-ok' : 'is-ko'}` }, c.status ? String(c.status) : '—')),
        el('div', { class: 'call__body' },
          el('div', {}, el('span', { class: 'call__label' }, 'Header'),
            el('pre', { class: 'call__json' }, c.auth ? 'X-Vault-Token: ‹the app\'s token, never shown›' : el('span', { class: 'is-error' }, 'no X-Vault-Token header'))),
          c.request ? el('div', {}, el('span', { class: 'call__label' }, 'Sent'), jsonNode(c.request)) : null,
          el('div', {}, el('span', { class: 'call__label' }, 'Answered'), jsonNode(c.response ?? {})))));
  }), ...(hidden ? [el('li', { class: 'wire__more' }, `… and ${hidden} more calls of the same kind`)] : []));
}

const strong = (t) => el('strong', {}, t);

// ---------- Archive and inspector ----------
function renderDeeds() {
  const { deeds, key, selected } = current;
  const min = key?.minDecryption ?? 1;
  $('deedCount').textContent = `${deeds.length} deed${deeds.length === 1 ? '' : 's'}`;
  $('deeds').replaceChildren(...deeds.map((d) => el('li', {},
    el('button', { type: 'button', class: `deed${d.ref === selected ? ' is-selected' : ''}${d.ref === current.fresh ? ' is-new' : ''}`, onclick: () => select(d.ref) },
      waxSeal(d.version, d.version < min),
      el('span', { class: 'deed__main' },
        el('span', { class: 'deed__title' }, d.title),
        el('span', { class: 'deed__meta' }, `${d.ref} · ${d.kind} · ${d.bytes} B`)),
      vBadge(d.version, d.version < min)))));
  current.fresh = null;
}

function renderRow(r, flash = false) {
  current.row = r;
  $('inspTitle').textContent = `${r.ref} · ${r.title}`;
  const locked = r.version < (current.key?.minDecryption ?? 1);
  $('inspVersion').replaceChildren(vBadge(r.version, locked));
  const line = (k, ...v) => [el('span', { class: 'k' }, k.padEnd(12)), ...v, '\n'];
  $('inspRow').replaceChildren(
    el('span', { class: 'c' }, `-- SELECT * FROM deeds WHERE ref = '${r.ref}';\n`),
    ...line('ref', r.ref),
    ...line('title', r.title),
    ...line('kind', r.kind),
    ...line('wrapped_key', el('span', { class: 'w' }, r.wrapped_key)),
    ...line('iv', r.iv),
    ...line('tag', r.tag),
    ...line('body', el('span', { class: 'x' }, `\\x${r.body}`), el('span', { class: 'c' }, `  (${r.bytes} bytes)`)),
    ...line('sealed_at', r.sealed_at),
    ...line('resealed_at', r.resealed_at ?? 'null'),
    el('span', { class: 'c' }, '-- body fingerprint: '), el('span', { class: 'f' }, r.bodyFingerprint));
  if (flash) { $('inspRow').classList.remove('is-flash'); void $('inspRow').offsetWidth; $('inspRow').classList.add('is-flash'); }
  $('openBtn').disabled = false;
  $('stealBtn').disabled = false;
}

async function select(ref, { flash = false } = {}) {
  current.selected = ref;
  $('reading').hidden = true;
  renderDeeds();
  try { renderRow(await api(`/api/deeds/${encodeURIComponent(ref)}`), flash); } catch (err) { $('inspTitle').textContent = err.message; }
}

function showReading(label, text, refused = false) {
  $('reading').hidden = false;
  $('reading').classList.toggle('is-refused', refused);
  $('readingLabel').textContent = label;
  $('readingText').textContent = text;
}

// ---------- Master key ----------
function renderKey() {
  const { key, deeds } = current;
  if (!key) return;
  $('keyName').textContent = key.name;
  $('keyType').textContent = key.type;
  const counts = new Map();
  for (const d of deeds) counts.set(d.version, (counts.get(d.version) ?? 0) + 1);
  $('versions').replaceChildren(...key.versions.map((v) => el('li', { class: `version${v.version === key.latest ? ' is-latest' : ''}${v.locked ? ' is-locked' : ''}` },
    vBadge(v.version, v.locked),
    el('span', {}, el('span', { class: 'version__when' }, v.locked ? 'locked' : (v.version === key.latest ? `latest · ${when(v.createdAt)}` : when(v.createdAt)))),
    el('span', { class: 'version__deeds' }, `${counts.get(v.version) ?? 0} deed${counts.get(v.version) === 1 ? '' : 's'}`))));
  const below = deeds.filter((d) => d.version < key.latest).length;
  $('rotateBtn').disabled = false;
  $('resealBtn').disabled = below === 0;
  const locked = key.minDecryption > 1;
  const lockBtn = $('lockBtn');
  lockBtn.textContent = locked ? 'Unlock' : 'Lock';
  lockBtn.classList.toggle('cc-btn--danger', !locked);
  lockBtn.disabled = !locked && key.latest === 1;
  $('keyHint').replaceChildren('The KMS keeps every version and never exports one. A sealed key says which version sealed it: ', el('code', {}, 'vault:v1:…'), '. A locked version is refused by the KMS.');
}

async function refresh() {
  const s = await api('/api/state');
  $('kmsHost').textContent = s.kms ? s.kms.host : 'KMS not configured';
  $('keyPath').textContent = s.kms ? `${s.kms.mount}/keys/${s.kms.key}` : 'transit/keys/…';
  const problem = $('bootProblem');
  problem.hidden = s.ready;
  problem.textContent = s.problem ?? '';
  $('platformVars').replaceChildren(...s.platform.map((p) => el('div', {}, el('dt', {}, p.name), el('dd', { class: p.value ? '' : 'is-empty' }, p.value ?? 'not set'))));
  current.deeds = s.deeds;
  current.key = s.key;
  renderDeeds();
  renderKey();
  return s;
}

async function act(button, fn) {
  if (busy) return;
  busy = true;
  button.disabled = true;
  try { await fn(); } catch (err) {
    renderWire([strong('Error: '), err.message], err.data?.calls ?? []);
  } finally {
    busy = false;
    button.disabled = false;
    renderKey();
  }
}

// ---------- Actions ----------
async function newDraft() {
  const d = await api('/api/draft');
  $('sealTitle').value = d.title;
  $('sealBody').value = d.body;
  $('sealKind').value = d.kind;
}

function wire() {
  $('draftBtn').addEventListener('click', () => newDraft());

  $('seal').addEventListener('submit', (e) => {
    e.preventDefault();
    act($('sealBtn'), async () => {
      $('sealError').hidden = true;
      try {
        const out = await api('/api/deeds', { method: 'POST', body: { title: $('sealTitle').value, body: $('sealBody').value, kind: $('sealKind').value || 'Deed' } });
        renderWire([strong(`Sealed ${out.ref}`), `: one call. The KMS drew a 256-bit data key and returned it twice, in clear (used once to encrypt, then wiped) and sealed by `, strong(`v${out.row.version}`), ' (stored next to the ciphertext).'], out.calls, 0, 'sealEcho');
        current.fresh = out.ref;
        await refresh();
        await select(out.ref, { flash: true });
        await newDraft();
      } catch (err) {
        $('sealError').hidden = false;
        $('sealError').textContent = err.message;
        throw err;
      }
    });
  });

  $('openBtn').addEventListener('click', () => act($('openBtn'), async () => {
    const ref = current.selected;
    const out = await api(`/api/deeds/${encodeURIComponent(ref)}/open`, { method: 'POST' });
    if (out.ok) {
      renderWire([strong(`Opened ${ref}`), ': the app sent the sealed key, the KMS checked the token and returned the data key. The app decrypted the deed itself and wiped the key. ', strong('The deed never went to the KMS.')], out.calls, 0, 'inspEcho');
      showReading(`Read by the notary · ${out.row.kind}`, out.text);
    } else {
      renderWire([strong(`Refused (${out.refused})`), `: ${ref} is sealed by v${out.row.version}, and the KMS no longer unseals that version. The app has nothing to decrypt with.`], out.calls, 0, 'inspEcho');
      showReading(`The KMS said no · HTTP ${out.refused}`, out.error, true);
    }
  }));

  $('stealBtn').addEventListener('click', () => act($('stealBtn'), async () => {
    const ref = current.selected;
    const out = await api(`/api/deeds/${encodeURIComponent(ref)}/steal`, { method: 'POST' });
    renderWire([strong('A stolen dump'), `: the thief has the whole row, sealed key included, but not the app's token. Same request to the KMS, without the header: `, strong(`${out.refused ?? out.calls[0]?.status}`), '. Without the data key, the body is noise.'], out.calls, 0, 'inspEcho');
    showReading(`What the thief gets · HTTP ${out.refused ?? '?'}`, `${out.error ?? 'Unexpected: the KMS answered'}\n\nbody = \\x${current.row?.body ?? ''}`, true);
  }));

  $('rotateBtn').addEventListener('click', () => act($('rotateBtn'), async () => {
    const out = await api('/api/key/rotate', { method: 'POST' });
    renderWire([strong(`Rotated: v${out.key.latest} is live.`), ' New deeds are sealed with it. Deeds sealed before still open with their own version: nothing was re-encrypted.'], out.calls, 0, 'rotateEcho');
    $('rotateOut').textContent = `v${out.key.latest} created in the KMS · 0 bytes of the archive touched`;
    await refresh();
  }));

  $('resealBtn').addEventListener('click', () => act($('resealBtn'), async () => {
    const before = current.row?.bodyFingerprint;
    const out = await api('/api/key/reseal', { method: 'POST' });
    const failed = out.refused.length;
    renderWire([strong(`Re-sealed ${out.resealed} envelope${out.resealed === 1 ? '' : 's'}`), ` to v${out.latest}: one rewrap call each. The KMS answered with a new sealed key, never the data key, and only the `, el('code', {}, 'wrapped_key'), ' column changed.', failed ? [' ', strong(`${failed} refused`), ': their version is locked, unlock first.'] : ''], out.calls, out.hiddenCalls, 'resealEcho');
    await refresh();
    if (current.selected) await select(current.selected, { flash: true });
    const same = before && current.row?.bodyFingerprint === before;
    const out2 = $('resealOut');
    out2.classList.toggle('is-ko', failed > 0);
    out2.textContent = `${out.resealed}/${out.candidates} re-sealed to v${out.latest}${failed ? ` · ${failed} refused (locked)` : ''}${same ? ` · ${current.selected} body unchanged: ${before}` : ''}`;
  }));

  $('lockBtn').addEventListener('click', () => act($('lockBtn'), async () => {
    const unlocking = (current.key?.minDecryption ?? 1) > 1;
    const out = await api(`/api/key/${unlocking ? 'unlock' : 'lock'}`, { method: 'POST' });
    const stale = current.deeds.filter((d) => d.version < out.key.latest).length;
    renderWire(unlocking
      ? [strong('Unlocked'), ': min_decryption_version is back to 1. Every version unseals again.']
      : [strong(`Locked below v${out.key.latest}`), `: the KMS will refuse to unseal any key sealed by an older version. ${stale} deed${stale === 1 ? '' : 's'} affected: open one.`], out.calls, 0, 'lockEcho');
    $('lockOut').classList.toggle('is-ko', !unlocking);
    $('lockOut').textContent = unlocking ? 'min_decryption_version = 1' : `min_decryption_version = ${out.key.latest} · ${stale} deed${stale === 1 ? '' : 's'} can no longer be opened`;
    await refresh();
    if (current.selected) await select(current.selected);
  }));
}

async function deep() {
  try {
    const d = await api('/health/deep');
    $('deepText').textContent = `KMS and PostgreSQL OK · key v${d.keyVersion} · ${d.deeds} deeds`;
  } catch (err) {
    $('deepPill').className = 'cc-pill cc-pill--muted';
    $('deepText').textContent = err.data?.problem ?? err.message;
  }
}

// The office may still be opening (KMS or database not ready yet): try again every 4 s.
async function load() {
  try {
    const s = await refresh();
    if (!s.ready) { setTimeout(load, 4000); return; }
    renderWire([strong('Page load'), ': the app read the master key\'s versions. No data travels in that call, only key metadata.'], s.calls);
    if (s.deeds.length) await select(s.deeds.at(-1).ref);
    deep();
  } catch (err) {
    $('bootProblem').hidden = false;
    $('bootProblem').textContent = err.message;
    setTimeout(load, 4000);
  }
}

wire();
newDraft().catch(() => {});
load();
