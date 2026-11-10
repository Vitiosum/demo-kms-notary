import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createApp, rateLimiter, clientIp } from '../server.js';
import { createKms } from '../src/kms.js';
import { fakeTransit, memoryStore } from './fakes.js';

const TOKEN = 'hvs.TEST-TOKEN-never-shown';
const transit = fakeTransit({ token: TOKEN });
const store = memoryStore();
const env = { VAULT_ADDR: 'https://kms.test:8200', VAULT_TOKEN: TOKEN, CC_APP_NAME: 'demo-kms-notary', SECRET_THING: 'nope' };
const quiet = { log() {}, error() {} };
let app;
let base;
const bodies = [];

async function call(path, { method = 'GET', body } = {}) {
  const res = await fetch(base + path, { method, headers: body ? { 'content-type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  bodies.push(text);
  let json = null;
  try { json = JSON.parse(text); } catch { /* html */ }
  return { status: res.status, json, text, headers: res.headers };
}

before(async () => {
  const kms = createKms({ addr: env.VAULT_ADDR, token: TOKEN, mount: 'transit', key: 'notary-master' }, { fetchImpl: transit.fetchImpl });
  app = createApp({ env, kms, store, log: quiet });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${app.server.address().port}`;
  await app.boot();
});

after(async () => {
  await app.close();
  // Nothing the app ever answered holds the token or a data key in clear.
  const all = bodies.join('\n');
  assert.ok(!all.includes(TOKEN), 'token leaked in a response');
  for (const p of transit.seen.plaintexts) assert.ok(!all.includes(p), 'data key leaked in a response');
  assert.ok(!all.includes('nope'), 'non-platform variable leaked');
});

test('start-up creates the master key and seals the five seed deeds', async () => {
  const s = await call('/api/state');
  assert.equal(s.status, 200);
  assert.equal(s.json.ready, true);
  assert.equal(s.json.deeds.length, 5);
  assert.equal(s.json.key.latest, 1);
  assert.equal(s.json.kms.host, 'kms.test:8200');
  assert.ok(s.json.deeds.every((d) => d.version === 1));
  assert.deepEqual(s.json.platform.find((p) => p.name === 'CC_APP_NAME'), { name: 'CC_APP_NAME', value: 'demo-kms-notary' });
});

test('the page and its assets are served with a strict CSP', async () => {
  const page = await call('/');
  assert.equal(page.status, 200);
  assert.match(page.text, /The Notary/);
  assert.match(page.headers.get('content-security-policy'), /default-src 'self'/);
  for (const p of ['/notary.js', '/notary.css', '/cc-brand.css']) assert.equal((await call(p)).status, 200);
  assert.equal((await call('/health')).status, 200);
  assert.equal((await call('/health/deep')).status, 200);
});

test('what PostgreSQL holds is unreadable: ciphertext and a sealed key', async () => {
  const r = await call('/api/deeds/NTR-0001');
  assert.equal(r.status, 200);
  assert.match(r.json.wrapped_key, /^vault:v1:/);
  assert.ok(!r.text.includes('Camille Ferrand'));
  assert.match(r.json.bodyFingerprint, /^sha256:[0-9a-f]{12}$/);
});

test('the notary opens a deed: one decrypt call, the deed never goes to the KMS', async () => {
  const r = await call('/api/deeds/NTR-0001/open', { method: 'POST' });
  assert.equal(r.json.ok, true);
  assert.match(r.json.text, /Camille Ferrand/);
  assert.deepEqual(r.json.calls.map((c) => c.path), ['/v1/transit/decrypt/notary-master']);
  assert.ok(!JSON.stringify(r.json.calls).includes('Camille'));
});

test('a thief without the token gets a 403', async () => {
  const r = await call('/api/deeds/NTR-0002/steal', { method: 'POST' });
  assert.equal(r.json.ok, false);
  assert.equal(r.json.refused, 403);
  assert.equal(r.json.calls[0].auth, false);
});

test('sealing a deed asks the KMS for one data key and stores only the sealed one', async () => {
  const r = await call('/api/deeds', { method: 'POST', body: { title: 'Lease of a test barn', body: 'Fictional text about a barn', kind: 'Lease' } });
  assert.equal(r.status, 201);
  assert.match(r.json.ref, /^NTR-/);
  assert.deepEqual(r.json.calls.map((c) => c.path), ['/v1/transit/datakey/plaintext/notary-master']);
  assert.ok(!r.text.includes('Fictional text about a barn'));
  const bad = await call('/api/deeds', { method: 'POST', body: { title: '', body: 'x' } });
  assert.equal(bad.status, 400);
});

test('rotate, lock, refuse, re-seal: the bodies never change', async () => {
  const fp = (await call('/api/deeds/NTR-0003')).json.bodyFingerprint;

  const rot = await call('/api/key/rotate', { method: 'POST' });
  assert.equal(rot.json.key.latest, 2);
  assert.equal((await call('/api/deeds/NTR-0003/open', { method: 'POST' })).json.ok, true, 'v1 still opens after a rotation');

  const lock = await call('/api/key/lock', { method: 'POST' });
  assert.equal(lock.json.key.minDecryption, 2);
  const refused = await call('/api/deeds/NTR-0003/open', { method: 'POST' });
  assert.equal(refused.json.ok, false);
  assert.equal(refused.json.refused, 400);
  assert.match(refused.json.error, /too old/);

  const blocked = await call('/api/key/reseal', { method: 'POST' });
  assert.equal(blocked.json.resealed, 0);
  assert.equal(blocked.json.refused.length, 6);

  await call('/api/key/unlock', { method: 'POST' });
  const re = await call('/api/key/reseal', { method: 'POST' });
  assert.equal(re.json.resealed, 6);
  assert.equal(re.json.calls.length, 7); // one key read, six rewraps

  const row = (await call('/api/deeds/NTR-0003')).json;
  assert.match(row.wrapped_key, /^vault:v2:/);
  assert.equal(row.bodyFingerprint, fp, 'the body was not re-encrypted');

  await call('/api/key/lock', { method: 'POST' });
  assert.equal((await call('/api/deeds/NTR-0003/open', { method: 'POST' })).json.ok, true, 're-sealed deeds open under the lock');
  await call('/api/key/unlock', { method: 'POST' });
});

test('unknown routes and refs answer 404', async () => {
  assert.equal((await call('/api/deeds/NTR-ZZZZ')).status, 404);
  assert.equal((await call('/api/deeds/../etc')).status, 404);
  assert.equal((await call('/nope')).status, 404);
});

test('rate limiter and client address', () => {
  const allow = rateLimiter(2, 1000);
  assert.equal(allow('a', 0), true);
  assert.equal(allow('a', 1), true);
  assert.equal(allow('a', 2), false);
  assert.equal(allow('a', 2000), true);
  assert.equal(clientIp({ headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2' }, socket: {} }), '2.2.2.2');
});

test('without the KMS variables, the app says what is missing and what to do', async () => {
  const bare = createApp({ env: { POSTGRESQL_ADDON_URI: 'postgresql:///none' }, store: memoryStore(), log: quiet });
  await new Promise((r) => bare.server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${bare.server.address().port}`;
  try {
    await bare.boot();
    assert.equal((await fetch(`${url}/health`)).status, 200);
    const deep = await fetch(`${url}/health/deep`);
    const body = await deep.json();
    assert.equal(deep.status, 503);
    assert.equal(body.problem, 'Missing VAULT_ADDR, VAULT_TOKEN');
    assert.match(body.nextStep, /private beta.*link it/);
    const state = await (await fetch(`${url}/api/state`)).json();
    assert.equal(state.ready, false);
    assert.equal(state.nextStep, body.nextStep);
  } finally { await bare.close(); }
});
