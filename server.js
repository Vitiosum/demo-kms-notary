// The Notary: every deed is encrypted with its own data key, and that key is sealed by a master key
// that never leaves Clever KMS. One Node.js server, no framework; the only dependency is `pg`.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';
import { kmsConfig, createKms } from './src/kms.js';
import { createStore, databaseUrl } from './src/store.js';
import { createNotary } from './src/notary.js';
import { checkDeed, draftDeed } from './src/deeds.js';

const PUBLIC = join(import.meta.dirname, 'public');
const TYPES = { '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.html': 'text/html; charset=utf-8' };
const STATIC = new Set(['/cc-brand.css', '/notary.css', '/notary.js']);
const PLATFORM_VARS = ['CC_APP_NAME', 'APP_ID', 'INSTANCE_NUMBER', 'INSTANCE_TYPE', 'CC_PRETTY_INSTANCE_NAME', 'CC_COMMIT_ID', 'CC_DEPLOYMENT_ID'];
const REF = /^NTR-[0-9A-Z]{4,8}$/;

// 40 actions per visitor per 10 minutes (counted per instance).
export function rateLimiter(limit = 40, windowMs = 10 * 60_000) {
  const hits = new Map();
  return (ip, now = Date.now()) => {
    const recent = (hits.get(ip) ?? []).filter((t) => now - t < windowMs);
    if (recent.length >= limit) { hits.set(ip, recent); return false; }
    recent.push(now);
    hits.set(ip, recent);
    if (hits.size > 5000) hits.delete(hits.keys().next().value);
    return true;
  };
}

// Behind the Clever Cloud load balancer, the last X-Forwarded-For entry is the address it saw.
export function clientIp(req) {
  const xff = String(req.headers['x-forwarded-for'] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  return xff.at(-1) || req.socket.remoteAddress || 'unknown';
}

async function readJson(req, limit = 4096) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw Object.assign(new Error('Body too large'), { status: 413 });
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || 'null'); } catch { throw Object.assign(new Error('Invalid JSON'), { status: 400 }); }
}

const CSP = [
  "default-src 'self'", "script-src 'self'", "style-src 'self' https://fonts.googleapis.com",
  'font-src https://fonts.gstatic.com', "img-src 'self' data:", "connect-src 'self'",
  "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
].join('; ');

export function createApp({ env = process.env, kms = undefined, store = undefined, log = console } = {}) {
  const cfg = kmsConfig(env);
  const url = databaseUrl(env);
  const kmsClient = kms ?? (cfg.ok ? createKms(cfg) : null);
  const db = store ?? (url ? createStore(url, { max: Number(env.PG_POOL_MAX) || 4 }) : null);
  const missing = [...cfg.missing, ...(url || store ? [] : ['POSTGRESQL_ADDON_URI'])];
  const notary = kmsClient && db ? createNotary({ kms: kmsClient, store: db }) : null;
  // What is left to do when a variable is missing: shown on the page and in /health/deep.
  const nextStep = cfg.missing.length
    ? 'Clever KMS is not linked to this app. It is a private beta opened per Clever Cloud user: ask the Clever Cloud team or the support for access, then create the KMS add-on, link it to the app (it injects VAULT_ADDR and VAULT_TOKEN) and restart.'
    : (missing.length ? 'Link the PostgreSQL add-on to the app (it injects POSTGRESQL_ADDON_URI) and restart.' : null);
  const state = { ready: false, problem: missing.length ? `Missing ${missing.join(', ')}` : 'Opening the office', bootCalls: [] };
  const allow = rateLimiter();
  const platform = PLATFORM_VARS.map((name) => ({ name, value: env[name] ?? null }));
  const kmsInfo = kmsClient ? { host: kmsClient.host, key: kmsClient.keyName, mount: kmsClient.mount } : null;

  async function boot(attempt = 1) {
    if (!notary) return;
    try {
      const { sealed, calls } = await notary.prepare();
      state.bootCalls = calls;
      state.ready = true;
      state.problem = null;
      log.log(`[notary] Ready: master key "${cfg.key}" on ${kmsClient.host}, ${sealed} seed deeds sealed`);
    } catch (err) {
      state.problem = `${err.kms ? 'KMS' : 'Database'}: ${err.message}`;
      const wait = Math.min(30_000, 1000 * 2 ** Math.min(attempt, 5));
      log.error(`[notary] Start-up attempt ${attempt} failed (${state.problem}), retry in ${wait / 1000} s`);
      setTimeout(() => boot(attempt + 1), wait).unref();
    }
  }

  function send(res, status, body, type = 'application/json; charset=utf-8') {
    const payload = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
    res.writeHead(status, {
      'content-type': type,
      'cache-control': 'no-store',
      'content-security-policy': CSP,
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'strict-transport-security': 'max-age=31536000',
    });
    res.end(payload);
  }

  async function handle(req, res) {
    const { pathname } = new URL(req.url, 'http://local');
    const method = req.method;

    if (method === 'GET' && pathname === '/health') return send(res, 200, { ok: true });
    if (method === 'GET' && pathname === '/health/deep') {
      if (!state.ready) return send(res, 503, { ok: false, problem: state.problem, ...(nextStep && { nextStep }) });
      try {
        await db.ping();
        const s = await notary.state();
        return send(res, s.key ? 200 : 503, { ok: Boolean(s.key), kms: kmsInfo.host, keyVersion: s.key?.latest ?? null, deeds: s.deeds.length });
      } catch (err) { return send(res, 503, { ok: false, problem: err.message }); }
    }

    if (method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
      return send(res, 200, await readFile(join(PUBLIC, 'index.html')), TYPES['.html']);
    }
    if (method === 'GET' && STATIC.has(pathname)) {
      return send(res, 200, await readFile(join(PUBLIC, pathname.slice(1))), TYPES[extname(pathname)]);
    }

    if (!pathname.startsWith('/api/')) return send(res, 404, { error: 'Not found' });
    if (method === 'GET' && pathname === '/api/draft') return send(res, 200, draftDeed());
    if (method === 'GET' && pathname === '/api/state') {
      const base = { ready: state.ready, problem: state.problem, nextStep, kms: kmsInfo, platform };
      if (!state.ready) return send(res, 200, { ...base, key: null, deeds: [], calls: [] });
      return send(res, 200, { ...base, ...(await notary.state()), bootCalls: state.bootCalls });
    }

    if (!state.ready) return send(res, 503, { error: state.problem });
    if (method === 'POST' && !allow(clientIp(req))) return send(res, 429, { error: 'Too many actions from your address: wait a few minutes' });

    if (method === 'POST' && pathname === '/api/deeds') {
      const checked = checkDeed(await readJson(req));
      if (!checked.ok) return send(res, 400, { error: checked.error });
      return send(res, 201, await notary.seal(checked.deed));
    }

    const m = /^\/api\/deeds\/([^/]+)(?:\/(open|steal))?$/.exec(pathname);
    if (m) {
      const ref = decodeURIComponent(m[1]);
      if (!REF.test(ref)) return send(res, 404, { error: 'No such deed' });
      let out = null;
      if (method === 'GET' && !m[2]) out = await notary.row(ref);
      else if (method === 'POST' && m[2] === 'open') out = await notary.open(ref);
      else if (method === 'POST' && m[2] === 'steal') out = await notary.steal(ref);
      else return send(res, 405, { error: 'Method not allowed' });
      return out ? send(res, 200, out) : send(res, 404, { error: 'No such deed' });
    }

    const actions = { '/api/key/rotate': 'rotate', '/api/key/reseal': 'reseal', '/api/key/lock': 'lock', '/api/key/unlock': 'unlock' };
    if (method === 'POST' && actions[pathname]) return send(res, 200, await notary[actions[pathname]]());

    return send(res, 404, { error: 'Not found' });
  }

  const server = createServer((req, res) => {
    handle(req, res).catch((err) => {
      const status = err.status && err.status < 500 && !err.kms ? err.status : (err.kms ? 502 : 500);
      if (status >= 500) log.error(`[notary] ${req.method} ${req.url}: ${err.message}`);
      if (!res.headersSent) send(res, status, { error: err.kms ? `KMS: ${err.message}` : (status >= 500 ? 'Internal error' : err.message) });
      else res.end();
    });
  });

  return { server, boot, state, close: async () => { server.close(); await db?.end?.(); } };
}

if (import.meta.main ?? process.argv[1] === import.meta.filename) {
  const app = createApp();
  const port = Number(process.env.PORT) || 8080;
  app.server.listen(port, '0.0.0.0', () => console.log(`[notary] Listening on 0.0.0.0:${port}`));
  app.boot();
  for (const sig of ['SIGTERM', 'SIGINT']) process.once(sig, () => app.close().finally(() => process.exit(0)));
}
