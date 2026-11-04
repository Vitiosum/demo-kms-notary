// Live proof: plays the whole story against a running Notary and checks every answer.
// Usage: node scripts/prove.mjs https://<your-app>.cleverapps.io   (defaults to http://127.0.0.1:8080)
// It seals one fictional deed, rotates the master key once and leaves it unlocked.
const BASE = (process.argv[2] || process.env.NOTARY_URL || 'http://127.0.0.1:8080').replace(/\/+$/, '');
const results = [];

async function api(path, method = 'GET', body) {
  const started = performance.now();
  const res = await fetch(BASE + path, { method, headers: body ? { 'content-type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, json, text, ms: Math.round(performance.now() - started) };
}

function check(name, ok, detail = '') {
  results.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? '✔' : '✖'} ${name}${detail ? `  (${detail})` : ''}`);
  return Boolean(ok);
}

const kmsCalls = (r) => (r.json?.calls ?? []).map((c) => `${c.method} ${c.path} → ${c.status}`).join(', ');

console.log(`The Notary, live proof against ${BASE}\n`);

const health = await api('/health');
check('GET /health answers 200', health.status === 200);
const deep = await api('/health/deep');
check('GET /health/deep: KMS and PostgreSQL answer', deep.status === 200, `KMS ${deep.json?.kms}, key v${deep.json?.keyVersion}`);

const state = await api('/api/state');
const L = state.json?.key?.latest;
check('The office is open: master key read from the KMS, seed deeds present', state.json?.ready && L >= 1 && state.json.deeds.length >= 5, `${state.json?.deeds?.length} deeds, key v${L}, ${kmsCalls(state)}`);

const row = await api('/api/deeds/NTR-0001');
check('PostgreSQL holds ciphertext and a sealed key, not the text', /^vault:v\d+:/.test(row.json?.wrapped_key) && !row.text.includes('Camille Ferrand'), `${row.json?.bytes} bytes, ${row.json?.wrapped_key?.slice(0, 14)}…`);

const open1 = await api('/api/deeds/NTR-0001/open', 'POST');
check('The notary opens NTR-0001: one decrypt call, text back', open1.json?.ok && open1.json.text.includes('Camille Ferrand') && open1.json.calls.length === 1, kmsCalls(open1));

const steal = await api('/api/deeds/NTR-0001/steal', 'POST');
check('A thief without the token gets 403 from the KMS', steal.json?.refused === 403 && steal.json.calls[0].auth === false, kmsCalls(steal));

const sealed = await api('/api/deeds', 'POST', { title: 'Proof: lease of a lighthouse keeper\'s cottage', body: 'Fictional deed sealed by scripts/prove.mjs. Rent: one painted pebble a month.', kind: 'Lease' });
const ref = sealed.json?.ref;
check('Sealing a deed: one datakey call, sealed by the latest version', sealed.status === 201 && sealed.json.row.version === L && !sealed.text.includes('painted pebble'), `${ref}, ${kmsCalls(sealed)}`);
const leaked = JSON.stringify(sealed.json?.calls ?? []);
check('The data key is never shown in clear', /kept in this app's memory only/.test(leaked) && !/"plaintext":"[A-Za-z0-9+/]{43}=/.test(leaked));

const rot = await api('/api/key/rotate', 'POST');
check('Rotation: the KMS adds a version', rot.json?.key?.latest === L + 1, `v${L} → v${rot.json?.key?.latest}`);
const openOld = await api(`/api/deeds/${ref}/open`, 'POST');
check(`${ref} (v${L}) still opens after the rotation, nothing re-encrypted`, openOld.json?.ok === true, kmsCalls(openOld));

const fpBefore = (await api(`/api/deeds/${ref}`)).json?.bodyFingerprint;
const lock = await api('/api/key/lock', 'POST');
check('Lock: min_decryption_version = latest', lock.json?.key?.minDecryption === L + 1, kmsCalls(lock));
const refused = await api(`/api/deeds/${ref}/open`, 'POST');
check(`${ref} (v${L}) is refused by the KMS while locked`, refused.json?.ok === false && refused.json.refused === 400, refused.json?.error);
const blocked = await api('/api/key/reseal', 'POST');
check('Re-sealing is refused too while locked', blocked.json?.resealed === 0 && blocked.json.refused.length >= 1, `${blocked.json?.refused?.length} refused`);

const unlock = await api('/api/key/unlock', 'POST');
check('Unlock: min_decryption_version back to 1', unlock.json?.key?.minDecryption === 1);
const reseal = await api('/api/key/reseal', 'POST');
check('Re-seal: every older sealed key rewrapped by the latest version', reseal.json?.resealed >= 1 && reseal.json.refused.length === 0, `${reseal.json?.resealed}/${reseal.json?.candidates} rewrapped`);
const after = (await api(`/api/deeds/${ref}`)).json;
check('Only the sealed key changed: same body fingerprint, new version', after?.bodyFingerprint === fpBefore && after?.version === L + 1, `${fpBefore} → ${after?.bodyFingerprint}, v${after?.version}`);

await api('/api/key/lock', 'POST');
const openNew = await api(`/api/deeds/${ref}/open`, 'POST');
check(`${ref} opens under the lock once re-sealed`, openNew.json?.ok === true);
const unlock2 = await api('/api/key/unlock', 'POST');
check('Left unlocked for the next visitor', unlock2.json?.key?.minDecryption === 1);

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
