// Validates db.js's generated SQL and result-shaping against every distinct
// query pattern used in api/[...path].js. Mocks Pool.prototype.query so this
// runs without a live database — run it any time you touch db.js, and again
// against a real Postgres database before trusting it in production.
//
// Usage:  npm install && npm test

process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgres://test:test@localhost:5432/test';

const { Pool } = require('pg');
const { createClient } = require('./db');

let lastCall = null;
let canned = { rows: [] };
Pool.prototype.query = async function (sql, params) {
  lastCall = { sql, params };
  return canned;
};

const db = createClient();
let failures = 0;
function check(name, cond) {
  if (!cond) { console.log('FAIL:', name); failures++; }
  else console.log('ok  :', name);
}

(async () => {
  canned = { rows: [{ id: 1, username: 'admin', is_active: true }] };
  let { data, error } = await db.from('main_admins').select('*').eq('username', 'admin').eq('is_active', true).single();
  check('select .eq.eq.single SQL', lastCall.sql === 'SELECT * FROM "main_admins" WHERE "username" = $1 AND "is_active" = $2');
  check('select .single shapes single object', data && data.id === 1 && error === null);

  canned = { rows: [] };
  ({ data, error } = await db.from('main_admins').select('*').eq('username', 'nope').single());
  check('single() with 0 rows returns null data + PGRST116 error', data === null && error && error.code === 'PGRST116');

  canned = { rows: [{ id: 9, admin_type: 'main', sub_admins: null }] };
  const nowIso = new Date().toISOString();
  await db.from('admin_sessions').select('*').eq('session_token_hash', 'abc').is('revoked_at', null).gt('expires_at', nowIso).single();
  check('is/gt SQL', lastCall.sql === 'SELECT * FROM "admin_sessions" WHERE "session_token_hash" = $1 AND "revoked_at" IS NULL AND "expires_at" > $2');

  canned = { rows: [{ id: 9, admin_type: 'sub', sub_admin_id: 5, sub_admins: { id: 5, name: 'Ali', is_active: true } }] };
  ({ data } = await db.from('admin_sessions').select('*, sub_admins(*)').eq('session_token_hash', 'xyz').is('revoked_at', null).single());
  check('embed SQL uses LEFT JOIN + row_to_json', lastCall.sql.includes('LEFT JOIN "sub_admins" e ON s."sub_admin_id" = e.id'));
  check('embed shapes nested sub_admins object', data.sub_admins && data.sub_admins.name === 'Ali');

  canned = { rows: [{ id: 3, super_admin_id: 7, super_admins: { id: 7, name: 'Sara' } }] };
  ({ data } = await db.from('factory_sessions').select('*, super_admins(*)').eq('session_token_hash', 'zzz').single());
  check('generalized embed picks correct FK column', lastCall.sql.includes('LEFT JOIN "super_admins" e ON s."super_admin_id" = e.id'));

  canned = { rows: [{ count: '2' }] };
  let countResult = await db.from('super_admins').select('*', { count: 'exact', head: true });
  check('count/head SQL', lastCall.sql === 'SELECT COUNT(*) AS count FROM "super_admins"');
  check('count/head returns numeric count, no data rows', countResult.count === 2 && countResult.data === null);

  canned = { rows: [{ id: 1 }, { id: 2 }] };
  let query = db.from('campaigns').select('*');
  query = query.eq('is_active', true);
  query = query.order('created_at', { ascending: false });
  ({ data } = await query);
  check('conditional builder + order DESC', lastCall.sql === 'SELECT * FROM "campaigns" WHERE "is_active" = $1 ORDER BY "created_at" DESC');

  canned = { rows: [{ id: 42, name: 'Test Campaign' }] };
  ({ data } = await db.from('campaigns').insert({ name: 'Test Campaign', is_active: true }).select().single());
  check('insert SQL has RETURNING *', lastCall.sql === 'INSERT INTO "campaigns" ("name", "is_active") VALUES ($1, $2) RETURNING *');

  canned = { rows: [{ id: 1 }, { id: 2 }, { id: 3 }] };
  ({ data } = await db.from('tweets').insert([{ campaign_id: 1, text: 'a' }, { campaign_id: 1, text: 'b' }, { campaign_id: 1, text: 'c' }]).select());
  check('bulk insert returns array of 3', Array.isArray(data) && data.length === 3);

  canned = { rows: [{ id: 5, is_active: false }] };
  ({ data } = await db.from('sub_admins').update({ is_active: false, updated_at: nowIso }).eq('id', 5).select('id, is_active').single());
  check('update SQL', lastCall.sql === 'UPDATE "sub_admins" SET "is_active" = $1, "updated_at" = $2 WHERE "id" = $3 RETURNING *');

  canned = { rows: [{}] };
  await db.from('sub_admins').update({ permissions: { canAddTweets: true } }).eq('id', 1);
  check('jsonb param is JSON-stringified', typeof lastCall.params[0] === 'string' && JSON.parse(lastCall.params[0]).canAddTweets === true);

  canned = { rows: [{ id: 7, name: 'Updated' }] };
  await db.from('campaigns').upsert({ id: 7, name: 'Updated' }, { onConflict: 'id' }).select().single();
  check('upsert SQL has ON CONFLICT DO UPDATE (excludes conflict col from SET)', lastCall.sql.includes('ON CONFLICT ("id") DO UPDATE SET') && !lastCall.sql.includes('"id" = EXCLUDED."id"'));

  canned = { rows: [] };
  await db.from('tweets').delete().eq('id', 99);
  check('delete SQL', lastCall.sql === 'DELETE FROM "tweets" WHERE "id" = $1');

  canned = { rows: [{ id: 1 }, { id: 2 }] };
  await db.from('admin_activity_logs').select('sub_admin_id, action_type').in('sub_admin_id', [1, 2, 3]);
  check('in() SQL', lastCall.sql === 'SELECT sub_admin_id, action_type FROM "admin_activity_logs" WHERE "sub_admin_id" IN ($1, $2, $3)');

  canned = { rows: [{ id: 1 }] };
  await db.from('admin_activity_logs').select('*').in('sub_admin_id', []);
  check('empty in() generates FALSE clause (matches nothing)', lastCall.sql.includes('WHERE FALSE'));

  canned = { rows: [{ org_name: 'Test Org' }] };
  ({ data } = await db.from('site_settings').select('*').limit(1).single());
  check('limit SQL', lastCall.sql === 'SELECT * FROM "site_settings" LIMIT 1');

  Pool.prototype.query = async function () {
    const err = new Error('duplicate key value violates unique constraint "sub_admins_username_key"');
    err.code = '23505';
    throw err;
  };
  ({ data, error } = await db.from('sub_admins').insert({ username: 'dup' }).select().single());
  check('unique violation returns {data:null, error} instead of throwing', data === null && error && error.message.includes('unique constraint'));

  console.log('\n' + (failures === 0 ? `ALL CHECKS PASSED` : `${failures} CHECK(S) FAILED`));
  process.exit(failures === 0 ? 0 : 1);
})();
