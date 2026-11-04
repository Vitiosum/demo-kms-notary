import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { seal, open, wipe } from '../src/envelope.js';
import { kmsConfig, keyVersionOf, describeKey, createKms } from '../src/kms.js';
import { checkDeed, draftDeed, newRef, SEED } from '../src/deeds.js';
import { fakeTransit } from './fakes.js';

test('a deed sealed with a data key opens with the same key and reference only', () => {
  const key = randomBytes(32);
  const sealed = seal('Fictional deed', key, 'NTR-0001');
  assert.equal(open(sealed, key, 'NTR-0001'), 'Fictional deed');
  assert.throws(() => open(sealed, key, 'NTR-0002'), /authenticate|bad decrypt/);
  assert.throws(() => open(sealed, randomBytes(32), 'NTR-0001'), /authenticate|bad decrypt/);
  assert.ok(!sealed.body.toString('utf8').includes('Fictional'));
});

test('wipe overwrites the data key', () => {
  const key = randomBytes(32);
  wipe(key);
  assert.ok(key.every((b) => b === 0));
});

test('KMS config reads VAULT_ADDR and VAULT_TOKEN, with defaults for the rest', () => {
  assert.deepEqual(kmsConfig({}).missing, ['VAULT_ADDR', 'VAULT_TOKEN']);
  const cfg = kmsConfig({ VAULT_ADDR: 'https://kms.example:8200/', VAULT_TOKEN: 't' });
  assert.equal(cfg.addr, 'https://kms.example:8200');
  assert.equal(cfg.mount, 'transit');
  assert.equal(cfg.key, 'notary-master');
});

test('key version is read from the sealed key prefix', () => {
  assert.equal(keyVersionOf('vault:v12:abc'), 12);
  assert.equal(keyVersionOf('nope'), null);
});

test('describeKey marks versions below min_decryption_version as locked', () => {
  const k = describeKey({ name: 'k', type: 'aes256-gcm96', latest_version: 3, min_decryption_version: 3, keys: { 3: 1793800000 } });
  assert.deepEqual(k.versions.map((v) => [v.version, v.locked]), [[3, false], [2, true], [1, true]]);
});

test('the call journal never holds the data key or the token', async () => {
  const t = fakeTransit({ token: 'tok-SECRET-123' });
  const kms = createKms({ addr: 'https://kms.test:8200', token: 'tok-SECRET-123', mount: 'transit', key: 'notary-master' }, { fetchImpl: t.fetchImpl });
  const s = kms.session();
  await s.ensureKey();
  const dk = await s.dataKey();
  await s.unwrap(dk.wrapped);
  const journal = JSON.stringify(s.calls);
  assert.ok(!journal.includes('tok-SECRET-123'));
  for (const p of t.seen.plaintexts) assert.ok(!journal.includes(p));
  assert.match(journal, /kept in this app's memory only/);
  assert.equal(s.calls.length, 3);
  assert.equal(kms.host, 'kms.test:8200');
});

test('without a token the KMS answers 403 and the call is recorded without the header', async () => {
  const t = fakeTransit();
  const kms = createKms({ addr: 'https://kms.test', token: t.token, mount: 'transit', key: 'notary-master' }, { fetchImpl: t.fetchImpl });
  const s = kms.session();
  await s.ensureKey();
  const dk = await s.dataKey();
  await assert.rejects(s.unwrapWithoutToken(dk.wrapped), (e) => e.kms && e.status === 403);
  assert.equal(s.calls.at(-1).auth, false);
  assert.equal(t.seen.calls.at(-1).token, null);
});

test('fictional deeds: fixed seed, random drafts, checked input', () => {
  assert.equal(SEED.length, 5);
  assert.match(newRef(), /^NTR-[0-9A-Z]{6}$/);
  const d = draftDeed();
  assert.ok(d.title && d.body && d.kind);
  assert.equal(checkDeed({ title: ' ', body: 'x' }).ok, false);
  assert.equal(checkDeed({ title: 'x'.repeat(121), body: 'x' }).ok, false);
  assert.equal(checkDeed({ title: 'T', body: 'B' }).ok, true);
});
