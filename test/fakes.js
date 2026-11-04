// Test doubles: a tiny Transit engine (same routes and errors as Clever KMS / Vault) and an
// in-memory archive with the same interface as src/store.js.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export function fakeTransit({ token = 'test-token', name = 'notary-master', mount = 'transit' } = {}) {
  const key = { versions: [], min: 1 };
  const seen = { plaintexts: [], calls: [] };
  const latest = () => key.versions.length;
  const rotate = () => { key.versions.push(randomBytes(32)); };
  const json = (status, body) => new Response(body === null ? '' : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const info = () => ({ data: { name, type: 'aes256-gcm96', latest_version: latest(), min_decryption_version: key.min, exportable: false, deletion_allowed: false, keys: Object.fromEntries(key.versions.map((_, i) => [String(i + 1), 1793800000 + i])) } });

  function wrap(plain, v) {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', key.versions[v - 1], iv);
    const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
    return `vault:v${v}:${Buffer.concat([iv, ct]).toString('base64')}`;
  }
  function unwrap(ciphertext) {
    const m = /^vault:v(\d+):(.+)$/.exec(ciphertext ?? '');
    if (!m) return { status: 400, errors: ['invalid ciphertext'] };
    const v = Number(m[1]);
    if (v < key.min) return { status: 400, errors: ['ciphertext or signature version is disallowed by policy (too old)'] };
    const raw = Buffer.from(m[2], 'base64');
    const d = createDecipheriv('aes-256-gcm', key.versions[v - 1], raw.subarray(0, 12));
    d.setAuthTag(raw.subarray(raw.length - 16));
    return { plain: Buffer.concat([d.update(raw.subarray(12, raw.length - 16)), d.final()]) };
  }

  async function fetchImpl(url, { method = 'GET', headers = {}, body } = {}) {
    const path = new URL(url).pathname.replace(`/v1/${mount}/`, '');
    seen.calls.push({ method, path, token: headers['X-Vault-Token'] ?? null });
    if (headers['X-Vault-Token'] !== token) return json(403, { errors: ['permission denied'] });
    const b = body ? JSON.parse(body) : {};
    const k = encodeURIComponent(name);
    if (method === 'POST' && path === `keys/${k}`) { if (!latest()) rotate(); return json(200, info()); }
    if (method === 'GET' && path === `keys/${k}`) return latest() ? json(200, info()) : json(404, { errors: [] });
    if (method === 'POST' && path === `keys/${k}/rotate`) { rotate(); return json(200, info()); }
    if (method === 'POST' && path === `keys/${k}/config`) {
      if (b.min_decryption_version > latest()) return json(400, { errors: ['cannot set min decryption version above latest version'] });
      key.min = b.min_decryption_version; return json(200, info());
    }
    if (method === 'POST' && path === `datakey/plaintext/${k}`) {
      const dk = randomBytes(b.bits / 8);
      seen.plaintexts.push(dk.toString('base64'));
      return json(200, { data: { plaintext: dk.toString('base64'), ciphertext: wrap(dk, latest()), key_version: latest() } });
    }
    if (method === 'POST' && path === `decrypt/${k}`) {
      const r = unwrap(b.ciphertext);
      return r.plain ? json(200, { data: { plaintext: r.plain.toString('base64') } }) : json(r.status, { errors: r.errors });
    }
    if (method === 'POST' && path === `rewrap/${k}`) {
      const r = unwrap(b.ciphertext);
      return r.plain ? json(200, { data: { ciphertext: wrap(r.plain, latest()), key_version: latest() } }) : json(r.status, { errors: r.errors });
    }
    return json(404, { errors: [`no handler for ${method} ${path}`] });
  }

  return { fetchImpl, seen, key, token };
}

export function memoryStore() {
  const rows = new Map();
  let clock = 0;
  const version = (w) => Number(/^vault:v(\d+):/.exec(w)?.[1] ?? 0);
  return {
    rows,
    migrate: async () => {},
    ping: async () => {},
    end: async () => {},
    async list() {
      return [...rows.values()].sort((a, b) => b.tick - a.tick)
        .map((r) => ({ ref: r.ref, title: r.title, kind: r.kind, seed: r.seed, version: version(r.wrapped_key), bytes: r.body.length, sealed_at: r.sealed_at, resealed_at: r.resealed_at }));
    },
    async get(ref) { const r = rows.get(ref); return r ? { ...r, version: version(r.wrapped_key) } : null; },
    async insert(d) {
      if (rows.has(d.ref)) return false;
      rows.set(d.ref, { ref: d.ref, title: d.title, kind: d.kind, seed: Boolean(d.seed), wrapped_key: d.wrapped, iv: d.iv, tag: d.tag, body: d.body, sealed_at: new Date().toISOString(), resealed_at: null, tick: clock++ });
      return true;
    },
    async refs() { return new Set(rows.keys()); },
    async replaceWrappedKey(ref, prev, next) {
      const r = rows.get(ref);
      if (!r || r.wrapped_key !== prev) return false;
      r.wrapped_key = next; r.resealed_at = new Date().toISOString();
      return true;
    },
    async below(v) { return [...rows.values()].filter((r) => version(r.wrapped_key) < v).map((r) => ({ ref: r.ref, wrapped_key: r.wrapped_key })); },
    async prune(keep) {
      const visitors = [...rows.values()].filter((r) => !r.seed).sort((a, b) => b.tick - a.tick);
      const gone = visitors.slice(keep);
      for (const r of gone) rows.delete(r.ref);
      return gone.length;
    },
  };
}
