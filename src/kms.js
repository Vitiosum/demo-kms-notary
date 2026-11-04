// Clever KMS speaks the HashiCorp Vault / OpenBao HTTP API. This app only uses its Transit engine:
// the master key is created, rotated and locked inside the KMS and never leaves it.
import { createHash } from 'node:crypto';

export function kmsConfig(env = process.env) {
  const addr = String(env.VAULT_ADDR ?? '').trim().replace(/\/+$/, '');
  const token = String(env.VAULT_TOKEN ?? '').trim();
  const missing = [!addr && 'VAULT_ADDR', !token && 'VAULT_TOKEN'].filter(Boolean);
  return {
    ok: missing.length === 0,
    missing,
    addr,
    token,
    mount: String(env.TRANSIT_MOUNT || 'transit').replace(/^\/+|\/+$/g, ''),
    key: env.KMS_KEY_NAME || 'notary-master',
  };
}

// "vault:v3:…" → 3
export function keyVersionOf(ciphertext) {
  const m = /^vault:v(\d+):/.exec(String(ciphertext ?? ''));
  return m ? Number(m[1]) : null;
}

export const fingerprint = (buf) => `sha256:${createHash('sha256').update(buf).digest('hex').slice(0, 12)}`;

// What the page may see of a KMS exchange: the wrapped keys are public by design (they sit in the
// database), the plaintext data key and the token never appear.
function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (!value || typeof value !== 'object') return value;
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (k === 'plaintext' && typeof v === 'string') {
      const bytes = Buffer.from(v, 'base64');
      out[k] = `‹${bytes.length}-byte data key, kept in this app's memory only (${fingerprint(bytes)})›`;
    } else if (['auth', 'wrap_info', 'client_token', 'token'].includes(k)) {
      out[k] = '‹hidden›';
    } else out[k] = redact(v);
  }
  return out;
}

// Only the fields worth showing; Vault answers with much more.
function trimResponse(data) {
  const d = data?.data;
  if (!d) return data?.errors ? { errors: data.errors } : null;
  if (d.keys && typeof d.keys === 'object' && !Array.isArray(d.keys)) {
    const { name, type, latest_version, min_decryption_version, exportable, deletion_allowed } = d;
    return { data: { name, type, latest_version, min_decryption_version, exportable, deletion_allowed } };
  }
  return { data: redact(d) };
}

export class KmsError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
    this.kms = true;
  }
}

export function createKms(cfg, { fetchImpl = globalThis.fetch, timeoutMs = 8000 } = {}) {
  const base = `${cfg.addr}/v1/${cfg.mount}`;
  const host = (() => { try { return new URL(cfg.addr).host; } catch { return cfg.addr; } })();

  // A session records every exchange made for one page action, so the page can show them.
  function session() {
    const calls = [];

    async function call(method, path, body, { auth = true } = {}) {
      const headers = { accept: 'application/json' };
      if (body) headers['content-type'] = 'application/json';
      if (auth) headers['X-Vault-Token'] = cfg.token;
      const entry = { method, path: `/v1/${cfg.mount}/${path}`, auth, request: body ? redact(body) : null, status: 0, ms: 0, response: null };
      calls.push(entry);
      const started = performance.now();
      let res;
      let data = null;
      try {
        res = await fetchImpl(`${base}/${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(timeoutMs) });
        const text = await res.text();
        try { data = text ? JSON.parse(text) : null; } catch { data = { errors: [text.slice(0, 200)] }; }
      } catch (err) {
        entry.ms = Math.round(performance.now() - started);
        entry.response = { errors: [`No answer from ${host}: ${err.name === 'TimeoutError' ? 'timeout' : err.message}`] };
        throw new KmsError(entry.response.errors[0], 502);
      }
      entry.ms = Math.round(performance.now() - started);
      entry.status = res.status;
      entry.response = trimResponse(data);
      if (!res.ok) throw new KmsError((data?.errors ?? []).join('; ') || `KMS answered ${res.status}`, res.status);
      return data?.data ?? null;
    }

    const k = encodeURIComponent(cfg.key);
    return {
      calls,
      // Idempotent: creating a key that exists changes nothing.
      ensureKey: () => call('POST', `keys/${k}`, { type: 'aes256-gcm96' }),
      readKey: () => call('GET', `keys/${k}`),
      // Envelope encryption: the KMS draws a fresh 256-bit data key and returns it twice,
      // in clear (used once, then wiped) and wrapped by the master key (stored).
      async dataKey() {
        const d = await call('POST', `datakey/plaintext/${k}`, { bits: 256 });
        return { key: Buffer.from(d.plaintext, 'base64'), wrapped: d.ciphertext, version: keyVersionOf(d.ciphertext) };
      },
      async unwrap(wrapped) {
        const d = await call('POST', `decrypt/${k}`, { ciphertext: wrapped });
        return Buffer.from(d.plaintext, 'base64');
      },
      async rewrap(wrapped) {
        const d = await call('POST', `rewrap/${k}`, { ciphertext: wrapped });
        return d.ciphertext;
      },
      rotate: () => call('POST', `keys/${k}/rotate`),
      lockBelow: (version) => call('POST', `keys/${k}/config`, { min_decryption_version: version }),
      // The same request a thief holding a database dump could make: no token.
      async unwrapWithoutToken(wrapped) {
        return call('POST', `decrypt/${k}`, { ciphertext: wrapped }, { auth: false });
      },
    };
  }

  return { host, keyName: cfg.key, mount: cfg.mount, session };
}

// The key as the page shows it: one line per version, locked when below min_decryption_version.
export function describeKey(info) {
  const latest = Number(info?.latest_version ?? 0);
  const min = Number(info?.min_decryption_version ?? 1);
  const created = info?.keys ?? {};
  const versions = [];
  for (let v = latest; v >= 1; v -= 1) {
    const ts = created[String(v)];
    versions.push({ version: v, locked: v < min, createdAt: typeof ts === 'number' ? new Date(ts * 1000).toISOString() : (typeof ts === 'string' ? ts : null) });
  }
  return { name: info?.name ?? null, type: info?.type ?? null, latest, minDecryption: min, exportable: Boolean(info?.exportable), versions };
}
