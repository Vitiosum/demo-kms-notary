// The notary's office: what each button on the page does, in plain steps.
import { describeKey, fingerprint, keyVersionOf } from './kms.js';
import { seal, open, wipe } from './envelope.js';
import { SEED, newRef } from './deeds.js';

export const MAX_VISITOR_DEEDS = 40;
const SHOWN_CALLS = 12;

const hex = (buf, max = 48) => {
  const h = Buffer.from(buf).toString('hex');
  return h.length > max * 2 ? `${h.slice(0, max * 2)}…` : h;
};

// Exactly what the row looks like to anyone reading the database: a DBA, a backup, a thief.
export function rowView(r) {
  return {
    ref: r.ref,
    title: r.title,
    kind: r.kind,
    version: r.version ?? keyVersionOf(r.wrapped_key),
    wrapped_key: r.wrapped_key,
    iv: hex(r.iv),
    tag: hex(r.tag),
    body: hex(r.body),
    bytes: r.body.length,
    bodyFingerprint: fingerprint(r.body),
    sealed_at: r.sealed_at,
    resealed_at: r.resealed_at,
  };
}

const capCalls = (calls) => calls.length <= SHOWN_CALLS
  ? { calls, hiddenCalls: 0 }
  : { calls: calls.slice(0, SHOWN_CALLS), hiddenCalls: calls.length - SHOWN_CALLS };

export function createNotary({ kms, store }) {
  async function sealInto(s, deed, { ref = newRef(), seedDeed = false } = {}) {
    const dk = await s.dataKey();
    try {
      const { iv, tag, body } = seal(deed.body, dk.key, ref);
      await store.insert({ ref, title: deed.title, kind: deed.kind, seed: seedDeed, wrapped: dk.wrapped, iv, tag, body });
      return ref;
    } finally {
      wipe(dk.key);
    }
  }

  return {
    // At start-up: the table, the master key (created once, inside the KMS), the five seed deeds.
    async prepare() {
      await store.migrate();
      const s = kms.session();
      await s.ensureKey();
      const present = await store.refs();
      let sealed = 0;
      for (const d of SEED) {
        if (present.has(d.ref)) continue;
        await sealInto(s, d, { ref: d.ref, seedDeed: true });
        sealed += 1;
      }
      return { sealed, calls: s.calls };
    },

    async state() {
      const s = kms.session();
      let key = null;
      let keyError = null;
      try { key = describeKey(await s.readKey()); } catch (err) { keyError = err.message; }
      const deeds = await store.list();
      return { key, keyError, deeds, calls: s.calls };
    },

    async seal(deed) {
      const s = kms.session();
      const ref = await sealInto(s, deed);
      const pruned = await store.prune(MAX_VISITOR_DEEDS);
      const row = await store.get(ref);
      return { ref, pruned, row: rowView(row), calls: s.calls };
    },

    async row(ref) {
      const r = await store.get(ref);
      return r ? rowView(r) : null;
    },

    // Authorised reading: the app asks the KMS to unwrap the data key, opens the deed, wipes the key.
    async open(ref) {
      const r = await store.get(ref);
      if (!r) return null;
      const s = kms.session();
      try {
        const key = await s.unwrap(r.wrapped_key);
        try {
          return { ok: true, text: open(r, key, r.ref), row: rowView(r), calls: s.calls };
        } finally {
          wipe(key);
        }
      } catch (err) {
        if (!err.kms) throw err;
        return { ok: false, refused: err.status, error: err.message, row: rowView(r), calls: s.calls };
      }
    },

    // What a stolen dump is worth: the same unwrap request, without the token.
    async steal(ref) {
      const r = await store.get(ref);
      if (!r) return null;
      const s = kms.session();
      try {
        await s.unwrapWithoutToken(r.wrapped_key);
        return { ok: true, refused: null, calls: s.calls };
      } catch (err) {
        if (!err.kms) throw err;
        return { ok: false, refused: err.status, error: err.message, row: rowView(r), calls: s.calls };
      }
    },

    async rotate() {
      const s = kms.session();
      await s.rotate();
      const key = describeKey(await s.readKey());
      return { key, calls: s.calls };
    },

    // Re-seal: every wrapped key below the latest version goes back to the KMS and comes back
    // wrapped by the latest one. The KMS never returns the data key; the deeds are not touched.
    async reseal() {
      const s = kms.session();
      const key = describeKey(await s.readKey());
      const rows = await store.below(key.latest);
      let resealed = 0;
      const refused = [];
      for (const r of rows) {
        try {
          const next = await s.rewrap(r.wrapped_key);
          if (await store.replaceWrappedKey(r.ref, r.wrapped_key, next)) resealed += 1;
        } catch (err) {
          if (!err.kms) throw err;
          refused.push({ ref: r.ref, status: err.status, error: err.message });
        }
      }
      return { latest: key.latest, candidates: rows.length, resealed, refused, ...capCalls(s.calls) };
    },

    // Lock: the KMS refuses to unwrap anything sealed by a version older than the latest.
    async lock() {
      const s = kms.session();
      const before = describeKey(await s.readKey());
      await s.lockBelow(before.latest);
      return { key: describeKey(await s.readKey()), calls: s.calls };
    },

    async unlock() {
      const s = kms.session();
      await s.lockBelow(1);
      return { key: describeKey(await s.readKey()), calls: s.calls };
    },
  };
}
