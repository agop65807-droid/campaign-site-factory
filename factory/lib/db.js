// ============================================================================
// db.js — a small, fluent Postgres query builder used throughout
// api/[...path].js: db.from('table').select('*').eq('col', val)...
//
// Every physical connection this pool opens is scoped to one Postgres
// SCHEMA via `SET search_path`, set from the DB_SCHEMA environment variable.
// This is what lets many tenants share a single Postgres server safely: each
// tenant's Vercel deployment gets the same DATABASE_URL but a different
// DB_SCHEMA, so every unqualified table reference in this codebase
// (campaigns, tweets, sub_admins, ...) resolves only against that tenant's
// own tables. See the project deployment guide for the full model.
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
    // (same-region) connections typically don't. Set PGSSLMODE=disable to turn
    // this off entirely.
    ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
    // Kept small: this runs inside a Vercel serverless function, where many
    // concurrent function instances can each hold their own pool, and every
    // tenant shares one Postgres server — max_connections adds up fast. Put
    // PgBouncer or Render's connection pooling in front rather than raising
    // this number if you outgrow it.
    max: 3,
    idleTimeoutMillis: 10000,
    connectionTimeoutMillis: 8000
  });

  // Scopes every new physical connection to this tenant's schema before any
  // query can run on it. Without DB_SCHEMA set, connections use the default
  // `public` schema — which is what the factory's own database uses.
  if (process.env.DB_SCHEMA) {
    pool.on('connect', (client) => {
      client.query(`SET search_path TO "${process.env.DB_SCHEMA}", public`).catch(err => {
        console.error('Failed to set search_path for new connection:', err.message);
      });
    });
  }

  return pool;
}

// jsonb/json column values need to arrive as JSON text — the pg driver
// doesn't serialize plain JS objects/arrays automatically.
function serializeParam(val) {
  if (val === undefined || val === null) return null;
  if (val instanceof Date) return val;
  if (Array.isArray(val) || typeof val === 'object') return JSON.stringify(val);
  return val;
}

function quoteIdent(name) {
  // Table/column names here are always string literals written in this
  // codebase, never taken from request bodies — this is a defensive quote,
  // not a security boundary. Still: reject anything that isn't a plain
  // identifier.
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) {
    throw new Error(`Refusing to use "${name}" as a SQL identifier`);
  }
  return `"${name}"`;
}

class QueryBuilder {
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
    this.embedTable = null;    // e.g. 'sub_admins' — a related table to join and nest in the result
    this.embedFkCol = null;    // e.g. 'sub_admin_id' — FK column on this table pointing at embedTable
    this.wantCountOnly = false; // select('*', { count: 'exact', head: true })
  }

  /**
   * select(cols) selects plain columns. select(cols, { count: 'exact', head: true })
   * runs a COUNT(*) instead. A column list containing "relatedTable(*)" (e.g.
   * '*, sub_admins(*)') joins that table and nests it in the result under
   * that key — the FK column is assumed to be <singular(relatedTable)>_id.
   */
  select(cols, opts) {
    if (opts && opts.head && opts.count === 'exact') {
      this.wantCountOnly = true;
      return this;
    }
    if (typeof cols === 'string') {
      const embedMatch = cols.match(/,?\s*([a-zA-Z_]+)\(\*\)/);
      if (embedMatch) {
        this.embedTable = embedMatch[1];
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

  // Makes the builder itself awaitable: `const { data, error } = await db.from(...).select(...)`.
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
        if (!Array.isArray(f.val) || f.val.length === 0) return 'FALSE'; // matches nothing
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
  return new QueryBuilder(table);
}

function createClient() {
  return { from };
}

module.exports = { createClient };
