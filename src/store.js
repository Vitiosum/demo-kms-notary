// The archive: one PostgreSQL table. It holds ciphertext, the wrapped data keys and an index card.
// The add-on is created with encryption at rest, so the disk is encrypted too: two layers.
import pg from 'pg';

export function databaseUrl(env = process.env) {
  return env.POSTGRESQL_ADDON_DIRECT_URI || env.POSTGRESQL_ADDON_URI || env.DATABASE_URL || '';
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS deeds (
  ref         text PRIMARY KEY,
  title       text NOT NULL,
  kind        text NOT NULL,
  seed        boolean NOT NULL DEFAULT false,
  wrapped_key text NOT NULL,
  iv          bytea NOT NULL,
  tag         bytea NOT NULL,
  body        bytea NOT NULL,
  sealed_at   timestamptz NOT NULL DEFAULT now(),
  resealed_at timestamptz
)`;

const VERSION = `coalesce(substring(wrapped_key from '^vault:v([0-9]+):')::int, 0)`;

export function createStore(url, { max = 4 } = {}) {
  const pool = new pg.Pool({ connectionString: url, max, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 8_000 });
  pool.on('error', (err) => console.error('[db] idle client error:', err.message));

  return {
    pool,
    migrate: () => pool.query(SCHEMA),
    ping: () => pool.query('SELECT 1'),
    end: () => pool.end(),

    async list() {
      const { rows } = await pool.query(
        `SELECT ref, title, kind, seed, ${VERSION} AS version, octet_length(body) AS bytes, sealed_at, resealed_at
           FROM deeds ORDER BY sealed_at DESC, ref DESC`);
      return rows;
    },

    async get(ref) {
      const { rows } = await pool.query(`SELECT *, ${VERSION} AS version FROM deeds WHERE ref = $1`, [ref]);
      return rows[0] ?? null;
    },

    async insert(d) {
      const { rowCount } = await pool.query(
        `INSERT INTO deeds (ref, title, kind, seed, wrapped_key, iv, tag, body)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (ref) DO NOTHING`,
        [d.ref, d.title, d.kind, Boolean(d.seed), d.wrapped, d.iv, d.tag, d.body]);
      return rowCount === 1;
    },

    async refs() {
      const { rows } = await pool.query('SELECT ref FROM deeds');
      return new Set(rows.map((r) => r.ref));
    },

    // Only the wrapped key changes on a re-seal; the body is not touched. Compare-and-set, so two
    // instances re-sealing at once cannot overwrite each other.
    async replaceWrappedKey(ref, previous, next) {
      const { rowCount } = await pool.query(
        'UPDATE deeds SET wrapped_key = $3, resealed_at = now() WHERE ref = $1 AND wrapped_key = $2',
        [ref, previous, next]);
      return rowCount === 1;
    },

    async below(version) {
      const { rows } = await pool.query(`SELECT ref, wrapped_key FROM deeds WHERE ${VERSION} < $1 ORDER BY ref`, [version]);
      return rows;
    },

    // Visitors' deeds beyond the cap are shredded, oldest first; the seed stays.
    async prune(keep) {
      const { rowCount } = await pool.query(
        `DELETE FROM deeds WHERE ref IN (
           SELECT ref FROM deeds WHERE NOT seed ORDER BY sealed_at DESC OFFSET $1)`, [keep]);
      return rowCount;
    },
  };
}
