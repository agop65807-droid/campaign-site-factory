// ============================================================================
// pg-supabase-shim.js
//
// A small adapter that implements the *subset* of the supabase-js v2 query
// builder actually used in api/[...path].js — .from().select().eq().is()
// .gt().in().order().limit().single(), plus .insert()/.update()/.upsert()/
// .delete() — backed by a plain PostgreSQL connection (`pg`) instead of
// Supabase's PostgREST API.
//
// WHY A SHIM INSTEAD OF REWRITING EVERY CALL SITE:
// api/[...path].js has ~40 distinct supabase.from(...) call chains spread
// across auth, sessions, campaigns, tweets, sub-admin permissions, invite
// links, analytics, and PDF report generation — code where a subtle
// behavioral slip (e.g. in the auth/session logic) is a real security risk.
// Re-implementing this adapter once, and testing it in isolation, is far
// lower-risk than hand-translating ~40 call sites and re-verifying all of
// that business logic by eye. The call sites did not change AT ALL — only
// this file's require() path changed at the top of api/[...path].js.
//
// MULTI-TENANCY MODEL: one shared Postgres server (one Render instance) hosts
// the factory's own tables AND every tenant's tables, isolated by Postgres
// SCHEMA rather than by separate database instances — every tenant gets its
// own `tenant_<slug>` schema on the same server. DATABASE_URL is therefore
// the SAME connection string for every tenant; what makes each tenant see
// only its own tables is DB_SCHEMA, an env var naming that tenant's schema.
// Every physical connection this pool opens runs `SET search_path` to that
// schema (via Pool's 'connect' event, below) BEFORE any query runs, so every
// unqualified table name already in api/[...path].js (campaigns, tweets, ...)
// keeps working completely unchanged — Postgres resolves them against
// whichever schema is first in search_path.
//
// COVERAGE: every distinct supabase.from(...) pattern in api/[...path].js
// was catalogued before writing this (grep for .from(/.select(/.eq(/.is(/
// .gt(/.in(/.order(/.limit(/.single(/.insert(/.update(/.upsert(/.delete().
// No .rpc(), .storage, or .auth usage exists in that file, so none of that
// is implemented here — this is deliberately not a general Supabase clone.
//
// The one embedded-relation select used in that file — .select('*,
// sub_admins(*)') on admin_sessions — is handled as a special case with a
// LEFT JOIN, since it's the only join pattern in the whole codebase.
// ============================================================================

const { Pool } = require('pg');

let pool = null;
function getPool() {
  if (pool) return pool;
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL is not set — cannot connect to Postgres');
  }
  pool = new Pool({
    connectionString,
    // Render's managed Postgres requires SSL for external connections; internal
    // (same-region) connections typically don't need it. rejectUnauthorized:false
    // is the pragmatic default for Render's self-signed-ish chain — set
    // PGSSLMODE=disable if you're connecting over Render's private network and
    // don't want SSL at all.
    ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
    // Kept small deliberately: this runs inside a Vercel serverless function,
    // where many concurrent function instances can each hold their own pool —
    // and now ALL tenants plus the factory share ONE Postgres server, so
    // max_connections adds up fast across tenants. Keep this low, and if you
    // outgrow it, put Render's connection pooling (or PgBouncer) in front
    // rather than just raising this number. See project README.
    max: 3,
    idleTimeoutMillis: 10000,
    connectionTimeoutMillis: 8000
  });

  // Every physical connection this pool opens gets its search_path set to
  // this tenant's own schema before any query can run on it — this is the
  // entire mechanism that lets many tenants (and the factory) share one
  // Postgres server safely. DB_SCHEMA is set per-tenant by the provisioning
  // pipeline (lib/tenantDb.js) as a Vercel env var alongside DATABASE_URL.
  // If DB_SCHEMA isn't set, the connection just uses the default `public`
  // schema — which is what the factory's own database connection does.
  if (process.env.DB_SCHEMA) {
    pool.on('connect', (client) => {
      client.query(`SET search_path TO "${process.env.DB_SCHEMA}", public`).catch(err => {
        console.error('Failed to set search_path for new connection:', err.message);
      });
    });
  }

  return pool;
}

// Values bound for jsonb/json columns need to arrive as JSON text; the pg
// driver does not do this automatically for plain JS objects/arrays.
function serializeParam(val) {
  if (val === undefined) return null;
  if (val === null) return null;
  if (val instanceof Date) return val;
  if (Array.isArray(val) || (typeof val === 'object')) return JSON.stringify(val);
  return val;
}

function quoteIdent(name) {
  // Table/column names in this codebase are always string literals written by
  // us, never taken from request bodies — so this is a defensive quote, not a
  // security boundary. Still: reject anything that isn't a plain identifier.
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) {
    throw new Error(`Refusing to use "${name}" as a SQL identifier`);
  }
  return `"${name}"`;
}

class PgQueryBuilder {
  constructor(table) {
    this.table = table;
    this.selectCols = '*';
    this.filters = []; // { col, op, val }
    this.orderCol = null;
    this.orderAsc = true;
    this.limitN = null;
    this.wantSingle = false;
    this.mode = 'select'; // 'select' | 'insert' | 'update' | 'upsert' | 'delete'
    this.payload = null;
    this.upsertConflictCol = 'id';
    this.embedTable = null;   // e.g. 'sub_admins' or 'super_admins' — generalized embed, see select()
    this.embedFkCol = null;   // e.g. 'sub_admin_id' — FK column on this table pointing at embedTable
    this.wantCountOnly = false; // select('*', { count: 'exact', head: true })
  }

  select(cols, opts) {
    if (opts && opts.head && opts.count === 'exact') {
      this.wantCountOnly = true;
      return this;
    }
    if (typeof cols === 'string') {
      const embedMatch = cols.match(/,?\s*([a-zA-Z_]+)\(\*\)/);
      if (embedMatch) {
        this.embedTable = embedMatch[1];
        // Heuristic: the FK column on THIS table pointing at the embedded table is
        // <singular-of-embed-table>_id — holds for every embed in this codebase
        // (sub_admins -> sub_admin_id, super_admins -> super_admin_id).
        this.embedFkCol = this.embedTable.replace(/s$/, '') + '_id';
        const rest = cols.replace(embedMatch[0], '').replace(/^,\s*/, '').trim();
        this.selectCols = rest || '*';
      } else {
        this.selectCols = cols;
      }
    }
    return this;
  }
  eq(col, val) { this.filters.push({ col, op: '=', val }); return this; }
  is(col, val) { this.filters.push({ col, op: 'IS', val }); return this; }
  gt(col, val) { this.filters.push({ col, op: '>', val }); return this; }
  in(col, vals) { this.filters.push({ col, op: 'IN', val: vals }); return this; }
  order(col, opts) { this.orderCol = col; this.orderAsc = !(opts && opts.ascending === false); return this; }
  limit(n) { this.limitN = n; return this; }
  single() { this.wantSingle = true; return this; }

  insert(obj) { this.mode = 'insert'; this.payload = obj; return this; }
  update(obj) { this.mode = 'update'; this.payload = obj; return this; }
  upsert(obj, opts) { this.mode = 'upsert'; this.payload = obj; this.upsertConflictCol = (opts && opts.onConflict) || 'id'; return this; }
  delete() { this.mode = 'delete'; return this; }

  // Makes the builder itself awaitable, matching supabase-js's ergonomics
  // (`const { data, error } = await supabase.from(...).select(...)`).
  then(onFulfilled, onRejected) {
    return this._exec().then(onFulfilled, onRejected);
  }

  async _exec() {
    try {
      return await this._run();
    } catch (err) {
      return { data: null, error: { message: err.message, code: err.code || null } };
    }
  }

  _buildWhere(paramsAcc, alias) {
    if (this.filters.length === 0) return '';
    const prefix = alias ? `${alias}.` : '';
    const clauses = this.filters.map(f => {
      if (f.op === 'IS') {
        return `${prefix}${quoteIdent(f.col)} IS ${f.val === null ? 'NULL' : 'NOT NULL'}`;
      }
      if (f.op === 'IN') {
        if (!Array.isArray(f.val) || f.val.length === 0) return 'FALSE'; // matches nothing, mirrors supabase behavior for empty .in()
        const placeholders = f.val.map(v => { paramsAcc.push(v); return `$${paramsAcc.length}`; });
        return `${prefix}${quoteIdent(f.col)} IN (${placeholders.join(', ')})`;
      }
      paramsAcc.push(serializeParam(f.val));
      return `${prefix}${quoteIdent(f.col)} ${f.op} $${paramsAcc.length}`;
    });
    return ' WHERE ' + clauses.join(' AND ');
  }

  async _run() {
    if (this.mode === 'select') return this._runSelect();
    if (this.mode === 'insert') return this._runInsert();
    if (this.mode === 'update') return this._runUpdate();
    if (this.mode === 'upsert') return this._runUpsert();
    if (this.mode === 'delete') return this._runDelete();
    throw new Error(`Unknown query mode: ${this.mode}`);
  }

  async _runSelect() {
    const params = [];
    let sql;

    if (this.wantCountOnly) {
      sql = `SELECT COUNT(*) AS count FROM ${quoteIdent(this.table)}`;
      sql += this._buildWhere(params);
      const { rows } = await getPool().query(sql, params);
      return { data: null, error: null, count: parseInt(rows[0].count, 10) };
    }

    if (this.embedTable) {
      // The embedded-relation pattern used a handful of times in this codebase
      // (e.g. admin_sessions -> sub_admins, factory_sessions -> super_admins):
      // a LEFT JOIN keyed on <singular(embedTable)>_id, computed in select().
      const cols = this.selectCols === '*' ? 's.*' : this.selectCols.split(',').map(c => `s.${quoteIdent(c.trim())}`).join(', ');
      sql = `SELECT ${cols}, row_to_json(e.*) AS ${quoteIdent(this.embedTable)} FROM ${quoteIdent(this.table)} s ` +
        `LEFT JOIN ${quoteIdent(this.embedTable)} e ON s.${quoteIdent(this.embedFkCol)} = e.id`;
      sql += this._buildWhere(params, 's');
    } else {
      sql = `SELECT ${this.selectCols === '*' ? '*' : this.selectCols} FROM ${quoteIdent(this.table)}`;
      sql += this._buildWhere(params);
    }
    if (this.orderCol) sql += ` ORDER BY ${quoteIdent(this.orderCol)} ${this.orderAsc ? 'ASC' : 'DESC'}`;
    if (this.limitN != null) sql += ` LIMIT ${parseInt(this.limitN, 10)}`;

    const { rows } = await getPool().query(sql, params);
    return this._shapeResult(rows);
  }

  async _runInsert() {
    const rowsIn = Array.isArray(this.payload) ? this.payload : [this.payload];
    if (rowsIn.length === 0) return this._shapeResult([]);
    const cols = Object.keys(rowsIn[0]);
    const params = [];
    const valueGroups = rowsIn.map(row => {
      const placeholders = cols.map(c => { params.push(serializeParam(row[c])); return `$${params.length}`; });
      return `(${placeholders.join(', ')})`;
    });
    const sql = `INSERT INTO ${quoteIdent(this.table)} (${cols.map(quoteIdent).join(', ')}) VALUES ${valueGroups.join(', ')} RETURNING *`;
    const { rows } = await getPool().query(sql, params);
    return this._shapeResult(rows);
  }

  async _runUpdate() {
    const cols = Object.keys(this.payload);
    const params = [];
    const setClause = cols.map(c => { params.push(serializeParam(this.payload[c])); return `${quoteIdent(c)} = $${params.length}`; }).join(', ');
    let sql = `UPDATE ${quoteIdent(this.table)} SET ${setClause}`;
    sql += this._buildWhere(params);
    sql += ' RETURNING *';
    const { rows } = await getPool().query(sql, params);
    return this._shapeResult(rows);
  }

  async _runUpsert() {
    const cols = Object.keys(this.payload);
    const params = [];
    const placeholders = cols.map(c => { params.push(serializeParam(this.payload[c])); return `$${params.length}`; });
    const updateCols = cols.filter(c => c !== this.upsertConflictCol);
    const updateClause = updateCols.map(c => `${quoteIdent(c)} = EXCLUDED.${quoteIdent(c)}`).join(', ');
    const sql = `INSERT INTO ${quoteIdent(this.table)} (${cols.map(quoteIdent).join(', ')}) VALUES (${placeholders.join(', ')}) ` +
      `ON CONFLICT (${quoteIdent(this.upsertConflictCol)}) DO UPDATE SET ${updateClause} RETURNING *`;
    const { rows } = await getPool().query(sql, params);
    return this._shapeResult(rows);
  }

  async _runDelete() {
    const params = [];
    const sql = `DELETE FROM ${quoteIdent(this.table)}` + this._buildWhere(params);
    await getPool().query(sql, params);
    return { data: null, error: null };
  }

  _shapeResult(rows) {
    const projected = rows.map(r => {
      if (this.embedTable) {
        const { [this.embedTable]: embedded, ...rest } = r;
        return { ...rest, [this.embedTable]: embedded || null };
      }
      return r;
    });
    if (this.wantSingle) {
      if (projected.length === 1) return { data: projected[0], error: null };
      return { data: null, error: { message: projected.length === 0 ? 'No rows found' : 'Multiple rows found', code: 'PGRST116' } };
    }
    return { data: projected, error: null };
  }
}

function from(table) {
  return new PgQueryBuilder(table);
}

// Mirrors `const { createClient } = require('@supabase/supabase-js')` so the
// require() line at the top of api/[...path].js only needed its target
// changed, not its usage.
function createClient() {
  return { from };
}

module.exports = { createClient };
