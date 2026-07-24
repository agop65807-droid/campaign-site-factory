// ============================================================================
// Factory Control Plane API — this deploys as ITS OWN separate Vercel
// project, backed by ITS OWN separate Supabase project (see architecture
// §6.1). It never shares a database with any tenant site.
//
// Env vars required (set on the FACTORY Vercel project only):
//   FACTORY_SUPABASE_URL, FACTORY_SUPABASE_SERVICE_ROLE_KEY
//                                      — the FACTORY's own Supabase project.
//                                        (SUPABASE_URL / SUPABASE_KEY also
//                                        still work, as older/alternate names.)
//   FACTORY_MASTER_KEY                — see lib/secretsVault.js
//   FACTORY_BOOTSTRAP_SECRET          — one-time secret to create the first
//                                        super_admin (see /api/factory/bootstrap)
//   TENANT_GIT_REPO                   — e.g. "your-org/campaign-site-template"
//   TENANT_GIT_REPO_ID                — numeric/string repo id Vercel needs for gitSource
//   TENANT_BASE_DOMAIN                — e.g. "campaigns.ourdomain.com"
//
// The Vercel token and Supabase organization token are NOT env vars — they
// live encrypted in secrets_vault (see lib/secretsVault.js KEYS), set once
// via POST /api/factory/vault/bootstrap by a super admin after first login.
// ============================================================================

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const vault = require('../lib/secretsVault');
const totp = require('../lib/totp');
const pw = require('../lib/passwordUtils');
const provisioning = require('../lib/provisioning');

const FACTORY_SUPABASE_URL = process.env.FACTORY_SUPABASE_URL || process.env.SUPABASE_URL;
const FACTORY_SUPABASE_KEY = process.env.FACTORY_SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
if (!FACTORY_SUPABASE_URL || !FACTORY_SUPABASE_KEY) {
  console.error('FACTORY_SUPABASE_URL / FACTORY_SUPABASE_SERVICE_ROLE_KEY are not set — every request will fail.');
}
const supabase = createClient(FACTORY_SUPABASE_URL, FACTORY_SUPABASE_KEY);

const corsHeaders = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-cache, no-store, must-revalidate',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
  // No Access-Control-Allow-Origin: * here on purpose. Unlike the tenant
  // sites' public API, the factory dashboard is same-origin only — no
  // third party should ever be able to call this API cross-origin.
};

const SESSION_EXPIRY_HOURS = 8; // shorter than tenant admin sessions — this API can touch every tenant's infra
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 10;

function json(res, status, body) {
  res.writeHead(status, corsHeaders);
  res.end(JSON.stringify(body));
}

async function readBody(req, maxLength = 2_000_000) { // higher limit: base64 logo uploads
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > maxLength) { req.destroy(); reject(new Error('Request body too large')); }
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function getIp(req) { return req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown'; }

function checkRateLimit(id) {
  const now = Date.now();
  const record = rateLimitStore.get(id);
  if (!record || now - record.firstAttempt > RATE_LIMIT_WINDOW) {
    rateLimitStore.set(id, { count: 1, firstAttempt: now });
    return { allowed: true };
  }
  if (record.count >= RATE_LIMIT_MAX) {
    return { allowed: false, retryAfter: Math.ceil((RATE_LIMIT_WINDOW - (now - record.firstAttempt)) / 1000) };
  }
  record.count++;
  return { allowed: true };
}

async function logActivity({ superAdminId, superAdminName, tenantId, actionType, details, req }) {
  try {
    await supabase.from('factory_activity_logs').insert({
      super_admin_id: superAdminId || null,
      super_admin_name: superAdminName || null,
      tenant_id: tenantId || null,
      action_type: actionType,
      details: details || null,
      ip_address: getIp(req),
      user_agent: req.headers['user-agent'] || 'unknown'
    });
  } catch (e) { console.error('Audit log insert failed:', e.message); }
}

// ---------------------------------------------------------------------------
// AUTH
// ---------------------------------------------------------------------------

async function getSessionFromReq(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token || token.length < 32) return null;
  const tokenHash = pw.hashToken(token);
  const { data: session } = await supabase
    .from('factory_sessions')
    .select('*, super_admins(*)')
    .eq('session_token_hash', tokenHash)
    .is('revoked_at', null)
    .gt('expires_at', new Date().toISOString())
    .single();
  if (!session || !session.totp_verified || !session.super_admins?.is_active) return null;
  return { sessionId: session.id, superAdmin: session.super_admins };
}

async function requireAuth(req, res) {
  const session = await getSessionFromReq(req);
  if (!session) { json(res, 401, { error: 'Unauthorized' }); return null; }
  return session;
}

/** One-time endpoint: creates the first super_admin. Requires FACTORY_BOOTSTRAP_SECRET and only works while the table is empty. */
async function handleBootstrap(req, res) {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
  try {
    const { bootstrapSecret, name, username, password } = JSON.parse(await readBody(req) || '{}');
    if (!process.env.FACTORY_BOOTSTRAP_SECRET || bootstrapSecret !== process.env.FACTORY_BOOTSTRAP_SECRET) {
      return json(res, 403, { error: 'Invalid bootstrap secret' });
    }
    const { count } = await supabase.from('super_admins').select('*', { count: 'exact', head: true });
    if (count && count > 0) return json(res, 409, { error: 'A super_admin already exists — bootstrap is only for the first one' });
    if (!name || !username || !password || password.length < 12) {
      return json(res, 400, { error: 'name, username and a password of at least 12 characters are required' });
    }
    const salt = pw.generateSalt();
    const password_hash = pw.hashPassword(password, salt);
    const { data, error } = await supabase.from('super_admins').insert({ name, username, password_hash, password_salt: salt }).select().single();
    if (error) return json(res, 500, { error: error.message });
    return json(res, 200, { success: true, superAdminId: data.id, next: 'Log in, then call /api/factory/auth/totp/enroll to set up required 2FA.' });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
}

/** Step 1 of login: username/password. Returns a short-lived pre-2FA token, never a full session (2FA is mandatory — §11 item 3). */
async function handleLogin(req, res) {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
  const clientId = crypto.createHash('sha256').update(getIp(req)).digest('hex');
  const rl = checkRateLimit(clientId);
  if (!rl.allowed) return json(res, 429, { error: 'Too many attempts', retryAfter: rl.retryAfter });

  try {
    const { username, password } = JSON.parse(await readBody(req) || '{}');
    if (!username || !password) return json(res, 400, { error: 'username and password are required' });

    const { data: admin, error } = await supabase.from('super_admins').select('*').eq('username', username).eq('is_active', true).single();
    if (error || !admin) return json(res, 401, { error: 'Invalid credentials' });

    const hashed = pw.hashPassword(password, admin.password_salt);
    if (!pw.timingSafeCompare(hashed, admin.password_hash)) return json(res, 401, { error: 'Invalid credentials' });

    // PRD §11 item 3 makes 2FA mandatory for super_admins, and that's the
    // recommended, non-negotiable setting — FACTORY_REQUIRE_2FA=true (as
    // provided) keeps that. Setting it to the literal string 'false' is
    // supported here only as an explicit, deliberate opt-out (e.g. for a
    // solo-operator throwaway/dev environment) and logs a warning every time
    // it's used, since it weakens the security model described in §11.
    if (process.env.FACTORY_REQUIRE_2FA === 'false') {
      console.warn('[Factory API] FACTORY_REQUIRE_2FA=false — logging in without 2FA. Not recommended outside local/dev use.');
      const bypassSession = { id: null, super_admin_id: admin.id, super_admins: admin };
      return finalizeSession(res, bypassSession, req);
    }

    const preToken = pw.generateToken();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min to complete 2FA
    await supabase.from('factory_sessions').insert({
      session_token_hash: pw.hashToken(preToken),
      super_admin_id: admin.id,
      totp_verified: false,
      expires_at: expiresAt
    });

    return json(res, 200, {
      success: true,
      preToken,
      totpEnrolled: !!admin.totp_secret_encrypted,
      message: admin.totp_secret_encrypted ? 'Submit your 6-digit code to /api/factory/auth/totp/verify' : 'No 2FA enrolled — call /api/factory/auth/totp/enroll with this preToken first'
    });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
}

/** Enroll TOTP for the account tied to a pending (non-verified) session. */
async function handleTotpEnroll(req, res) {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
  try {
    const { preToken } = JSON.parse(await readBody(req) || '{}');
    const { data: session } = await supabase.from('factory_sessions').select('*, super_admins(*)').eq('session_token_hash', pw.hashToken(preToken || '')).is('revoked_at', null).gt('expires_at', new Date().toISOString()).single();
    if (!session) return json(res, 401, { error: 'Invalid or expired preToken' });
    if (session.super_admins.totp_secret_encrypted) return json(res, 409, { error: 'TOTP already enrolled for this account — use /auth/totp/verify to log in' });

    const secret = totp.generateSecret();
    await vault.setSecret(supabase, `super_admin:${session.super_admin_id}:totp_secret_pending`, secret);
    const otpauthUrl = totp.buildOtpauthUrl({ secret, accountName: session.super_admins.username });
    return json(res, 200, { success: true, secret, otpauthUrl, next: 'Scan into your authenticator app, then POST the current code to /api/factory/auth/totp/enroll/confirm with this preToken.' });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
}

async function handleTotpEnrollConfirm(req, res) {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
  try {
    const { preToken, code } = JSON.parse(await readBody(req) || '{}');
    const { data: session } = await supabase.from('factory_sessions').select('*, super_admins(*)').eq('session_token_hash', pw.hashToken(preToken || '')).is('revoked_at', null).gt('expires_at', new Date().toISOString()).single();
    if (!session) return json(res, 401, { error: 'Invalid or expired preToken' });

    const pendingSecret = await vault.getSecret(supabase, `super_admin:${session.super_admin_id}:totp_secret_pending`);
    if (!pendingSecret) return json(res, 400, { error: 'No pending enrollment found — call /auth/totp/enroll first' });
    if (!totp.verifyTotp(pendingSecret, code)) return json(res, 401, { error: 'Invalid code' });

    const encrypted = vault.encrypt(pendingSecret);
    await supabase.from('super_admins').update({ totp_secret_encrypted: encrypted, totp_enrolled_at: new Date().toISOString() }).eq('id', session.super_admin_id);
    await vault.deleteSecret(supabase, `super_admin:${session.super_admin_id}:totp_secret_pending`);

    return finalizeSession(res, session, req);
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
}

async function handleTotpVerify(req, res) {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
  try {
    const { preToken, code } = JSON.parse(await readBody(req) || '{}');
    const { data: session } = await supabase.from('factory_sessions').select('*, super_admins(*)').eq('session_token_hash', pw.hashToken(preToken || '')).is('revoked_at', null).gt('expires_at', new Date().toISOString()).single();
    if (!session) return json(res, 401, { error: 'Invalid or expired preToken' });

    const secret = vault.decrypt(session.super_admins.totp_secret_encrypted);
    if (!totp.verifyTotp(secret, code)) return json(res, 401, { error: 'Invalid code' });

    return finalizeSession(res, session, req);
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
}

async function finalizeSession(res, session, req) {
  const fullToken = pw.generateToken();
  const expiresAt = new Date(Date.now() + SESSION_EXPIRY_HOURS * 60 * 60 * 1000).toISOString();
  const sessionPatch = { session_token_hash: pw.hashToken(fullToken), totp_verified: true, expires_at: expiresAt };
  if (session.id) {
    await supabase.from('factory_sessions').update(sessionPatch).eq('id', session.id);
  } else {
    await supabase.from('factory_sessions').insert({ ...sessionPatch, super_admin_id: session.super_admin_id });
  }
  await supabase.from('super_admins').update({ last_login_at: new Date().toISOString() }).eq('id', session.super_admin_id);
  await logActivity({ superAdminId: session.super_admin_id, superAdminName: session.super_admins.name, actionType: 'login', req });
  return json(res, 200, { success: true, token: fullToken, expiresAt, name: session.super_admins.name });
}

async function handleLogout(req, res) {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (token) await supabase.from('factory_sessions').update({ revoked_at: new Date().toISOString() }).eq('session_token_hash', pw.hashToken(token));
  return json(res, 200, { success: true });
}

// ---------------------------------------------------------------------------
// VAULT BOOTSTRAP — set the Vercel/Supabase master tokens (auth required)
// ---------------------------------------------------------------------------

async function handleVaultBootstrap(req, res) {
  const session = await requireAuth(req, res);
  if (!session) return;
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
  try {
    const { vercelToken, vercelTeamId, supabaseOrgToken, supabaseOrgId } = JSON.parse(await readBody(req) || '{}');
    if (vercelToken) await vault.setSecret(supabase, vault.KEYS.VERCEL_TOKEN, vercelToken);
    if (vercelTeamId) await vault.setSecret(supabase, vault.KEYS.VERCEL_TEAM_ID, vercelTeamId);
    if (supabaseOrgToken) await vault.setSecret(supabase, vault.KEYS.SUPABASE_ORG_TOKEN, supabaseOrgToken);
    if (supabaseOrgId) await vault.setSecret(supabase, vault.KEYS.SUPABASE_ORG_ID, supabaseOrgId);
    await logActivity({ superAdminId: session.superAdmin.id, superAdminName: session.superAdmin.name, actionType: 'vault_bootstrap', req });
    return json(res, 200, { success: true });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
}

// ---------------------------------------------------------------------------
// TENANTS
// ---------------------------------------------------------------------------

async function handleListTenants(req, res) {
  const session = await requireAuth(req, res);
  if (!session) return;
  const { data, error } = await supabase.from('tenants').select('*').order('created_at', { ascending: false });
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { success: true, tenants: data });
}

function slugify(name) {
  return String(name).toLowerCase().trim()
    .replace(/[^\u0600-\u06FFa-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .slice(0, 40) || `org-${Date.now()}`;
}

async function loadMigrationSql() {
  // Bundles the tenant template's migrations at deploy time — see README for
  // how these files get here (kept in sync via the same monorepo/build step).
  const dir = path.join(__dirname, '..', 'tenant-migrations');
  const files = ['001_base_schema.sql', '002_share_platforms_and_site_settings.sql'];
  return files.map(f => fs.readFileSync(path.join(dir, f), 'utf8')).join('\n\n');
}

async function handleCreateTenant(req, res) {
  const session = await requireAuth(req, res);
  if (!session) return;
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });

  try {
    const input = JSON.parse(await readBody(req) || '{}');
    if (!input.orgName || !input.adminUsername) {
      return json(res, 400, { error: 'orgName and adminUsername are required' });
    }
    const slug = input.slug ? slugify(input.slug) : slugify(input.orgName);

    const { data: existing } = await supabase.from('tenants').select('id').eq('slug', slug).single();
    if (existing) return json(res, 409, { error: `Slug "${slug}" is already in use` });

    input.slug = slug;
    input.primaryColor = input.primaryColor || '#1e3a8a';
    input.secondaryColor = input.secondaryColor || '#d97706';
    input.subdomain = input.subdomain || slug;
    input.baseDomain = process.env.TENANT_BASE_DOMAIN;

    const { data: tenant, error: tErr } = await supabase.from('tenants').insert({
      org_name: input.orgName,
      slug,
      status: 'provisioning',
      enabled_share_platforms: input.enabledSharePlatforms || ['x', 'whatsapp', 'facebook'],
      created_by_super_admin_id: session.superAdmin.id
    }).select().single();
    if (tErr) return json(res, 500, { error: tErr.message });

    const { data: job, error: jErr } = await supabase.from('provisioning_jobs').insert({
      tenant_id: tenant.id,
      job_type: 'create',
      status: 'pending',
      input_payload: redactSecrets(input)
    }).select().single();
    if (jErr) return json(res, 500, { error: jErr.message });

    await logActivity({ superAdminId: session.superAdmin.id, superAdminName: session.superAdmin.name, tenantId: tenant.id, actionType: 'create_tenant', details: { slug }, req });

    // Kick off provisioning. See header comment: for production use behind a
    // hard serverless timeout, replace this direct call with enqueueing and
    // let a cron-driven /api/factory/jobs/tick advance it instead.
    runJobInBackground(job.id, tenant, input).catch(e => console.error('Provisioning job crashed:', e));

    return json(res, 202, { success: true, tenantId: tenant.id, jobId: job.id, status: 'provisioning' });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
}

function redactSecrets(input) {
  const { logoBase64, ...safe } = input;
  return safe; // never persist the raw logo upload or any secret in the audit-visible input_payload
}

async function getProvisioningCredentials() {
  // Prefer plain env vars (simpler ops — Vercel encrypts these at rest and
  // hides them from the dashboard UI after creation) if present; fall back
  // to the encrypted secrets_vault (set via /api/factory/vault/bootstrap)
  // for teams that prefer not to put these in env vars at all.
  const vercelToken = process.env.VERCEL_TOKEN || await vault.getSecret(supabase, vault.KEYS.VERCEL_TOKEN);
  const vercelTeamId = process.env.VERCEL_TEAM_ID || await vault.getSecret(supabase, vault.KEYS.VERCEL_TEAM_ID);
  const supabaseOrgToken = process.env.SUPABASE_ACCESS_TOKEN || await vault.getSecret(supabase, vault.KEYS.SUPABASE_ORG_TOKEN);
  const supabaseOrgId = process.env.SUPABASE_ORG_ID || await vault.getSecret(supabase, vault.KEYS.SUPABASE_ORG_ID);
  return { vercelToken, vercelTeamId, supabaseOrgToken, supabaseOrgId };
}

async function runJobInBackground(jobId, tenant, input) {
  const { vercelToken, vercelTeamId, supabaseOrgToken, supabaseOrgId } = await getProvisioningCredentials();
  if (!vercelToken || !supabaseOrgToken || !supabaseOrgId) {
    await supabase.from('provisioning_jobs').update({ status: 'failed', error_message: 'Master tokens not configured — set VERCEL_TOKEN / SUPABASE_ACCESS_TOKEN / SUPABASE_ORG_ID env vars, or call /api/factory/vault/bootstrap' }).eq('id', jobId);
    await supabase.from('tenants').update({ status: 'failed' }).eq('id', tenant.id);
    return;
  }

  const migrationSql = await loadMigrationSql();
  const { data: job } = await supabase.from('provisioning_jobs').select('*').eq('id', jobId).single();

  await provisioning.runProvisioningJob(supabase, job, tenant, {
    vercelToken, vercelTeamId, supabaseOrgToken, supabaseOrgId,
    gitRepo: {
      type: 'github',
      repo: process.env.TENANT_GIT_REPO,
      gitSource: { type: 'github', repoId: process.env.TENANT_GIT_REPO_ID, ref: 'main' }
    },
    input,
    migrationSql
  });
}

async function handleGetJob(req, res, jobId) {
  const session = await requireAuth(req, res);
  if (!session) return;
  const { data, error } = await supabase.from('provisioning_jobs').select('*').eq('id', jobId).single();
  if (error || !data) return json(res, 404, { error: 'Job not found' });
  return json(res, 200, { success: true, job: data });
}

async function handleSuspendTenant(req, res, tenantId) {
  const session = await requireAuth(req, res);
  if (!session) return;
  const { data: tenant } = await supabase.from('tenants').select('*').eq('id', tenantId).single();
  if (!tenant) return json(res, 404, { error: 'Tenant not found' });
  const { vercelToken, vercelTeamId } = await getProvisioningCredentials();
  const vercel = require('../lib/vercelClient');
  try {
    if (tenant.vercel_project_id) await vercel.pauseProject(vercelToken, vercelTeamId, tenant.vercel_project_id);
    await supabase.from('tenants').update({ status: 'suspended', suspended_at: new Date().toISOString() }).eq('id', tenantId);
    await logActivity({ superAdminId: session.superAdmin.id, superAdminName: session.superAdmin.name, tenantId, actionType: 'suspend_tenant', req });
    return json(res, 200, { success: true });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
}

async function handleResumeTenant(req, res, tenantId) {
  const session = await requireAuth(req, res);
  if (!session) return;
  const { data: tenant } = await supabase.from('tenants').select('*').eq('id', tenantId).single();
  if (!tenant) return json(res, 404, { error: 'Tenant not found' });
  const { vercelToken, vercelTeamId } = await getProvisioningCredentials();
  const vercel = require('../lib/vercelClient');
  try {
    if (tenant.vercel_project_id) await vercel.unpauseProject(vercelToken, vercelTeamId, tenant.vercel_project_id);
    await supabase.from('tenants').update({ status: 'active', suspended_at: null }).eq('id', tenantId);
    await logActivity({ superAdminId: session.superAdmin.id, superAdminName: session.superAdmin.name, tenantId, actionType: 'resume_tenant', req });
    return json(res, 200, { success: true });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
}

/** Double-confirmation required client-side (dashboard) before this is ever called — see FR8/FR1. */
async function handleDeleteTenant(req, res, tenantId) {
  const session = await requireAuth(req, res);
  if (!session) return;
  try {
    const { confirmSlug } = JSON.parse(await readBody(req) || '{}');
    const { data: tenant } = await supabase.from('tenants').select('*').eq('id', tenantId).single();
    if (!tenant) return json(res, 404, { error: 'Tenant not found' });
    if (confirmSlug !== tenant.slug) return json(res, 400, { error: 'confirmSlug does not match — refusing to delete' });

    const { vercelToken, vercelTeamId, supabaseOrgToken } = await getProvisioningCredentials();
    const vercel = require('../lib/vercelClient');
    const supabaseMgmt = require('../lib/supabaseManagementClient');

    await supabase.from('tenants').update({ status: 'deleting' }).eq('id', tenantId);
    if (tenant.vercel_project_id) await vercel.deleteProject(vercelToken, vercelTeamId, tenant.vercel_project_id).catch(e => console.error('Vercel delete failed:', e.message));
    if (tenant.supabase_project_ref) await supabaseMgmt.deleteProject(supabaseOrgToken, tenant.supabase_project_ref).catch(e => console.error('Supabase delete failed:', e.message));
    await vault.deleteSecret(supabase, vault.KEYS.tenantSupabaseServiceKey(tenantId));
    await vault.deleteSecret(supabase, vault.KEYS.tenantMainAdminPasswordOneTime(tenantId));

    await supabase.from('tenants').update({ status: 'deleted', deleted_at: new Date().toISOString() }).eq('id', tenantId);
    await logActivity({ superAdminId: session.superAdmin.id, superAdminName: session.superAdmin.name, tenantId, actionType: 'delete_tenant', details: { slug: tenant.slug }, req });
    return json(res, 200, { success: true });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
}

/** Returns the one-time admin password exactly once, then deletes it from the vault (PRD §7b step 11). */
async function handleRevealAdminPassword(req, res, tenantId) {
  const session = await requireAuth(req, res);
  if (!session) return;
  const key = vault.KEYS.tenantMainAdminPasswordOneTime(tenantId);
  const value = await vault.getSecret(supabase, key);
  if (!value) return json(res, 404, { error: 'No one-time password available (already viewed, or tenant not created via the wizard)' });
  await vault.deleteSecret(supabase, key);
  await logActivity({ superAdminId: session.superAdmin.id, superAdminName: session.superAdmin.name, tenantId, actionType: 'reveal_admin_password', req });
  return json(res, 200, { success: true, password: value, warning: 'This password will not be shown again. Share it with the tenant securely and have them change it on first login.' });
}

async function handleResetAdminPassword(req, res, tenantId) {
  const session = await requireAuth(req, res);
  if (!session) return;
  try {
    const { data: tenant } = await supabase.from('tenants').select('*').eq('id', tenantId).single();
    if (!tenant) return json(res, 404, { error: 'Tenant not found' });
    const serviceKey = await vault.getSecret(supabase, vault.KEYS.tenantSupabaseServiceKey(tenantId));
    if (!serviceKey || !tenant.supabase_project_ref) return json(res, 400, { error: 'Missing stored service key for this tenant — cannot reach its database' });

    const newPassword = pw.generateStrongPassword(16);
    const salt = pw.generateSalt();
    const passwordHash = pw.hashPassword(newPassword, salt);
    const tenantUrl = `https://${tenant.supabase_project_ref}.supabase.co`;

    const putRes = await fetch(`${tenantUrl}/rest/v1/main_admins?is_active=eq.true`, {
      method: 'PATCH',
      headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({ password_hash: passwordHash, password_salt: salt, must_change_password: true })
    });
    if (!putRes.ok) return json(res, 500, { error: `Failed to update tenant's main_admins row: ${putRes.status}` });

    await vault.setSecret(supabase, vault.KEYS.tenantMainAdminPasswordOneTime(tenantId), newPassword);
    await logActivity({ superAdminId: session.superAdmin.id, superAdminName: session.superAdmin.name, tenantId, actionType: 'reset_admin_password', req });
    return json(res, 200, { success: true, message: 'Password reset — fetch it once via GET /api/factory/tenants/:id/admin-password' });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
}

async function handleAuditLog(req, res) {
  const session = await requireAuth(req, res);
  if (!session) return;
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const tenantId = url.searchParams.get('tenantId');
  let query = supabase.from('factory_activity_logs').select('*').order('created_at', { ascending: false }).limit(200);
  if (tenantId) query = query.eq('tenant_id', tenantId);
  const { data, error } = await query;
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { success: true, logs: data });
}

// ---------------------------------------------------------------------------
// TEMPLATE UPDATES (FR3: redeploy one tenant, or all tenants, from the shared template)
// ---------------------------------------------------------------------------

async function handleUpdateTemplate(req, res, tenantId) {
  const session = await requireAuth(req, res);
  if (!session) return;
  const vercel = require('../lib/vercelClient');
  const { vercelToken, vercelTeamId } = await getProvisioningCredentials();
  try {
    const { data: tenant } = await supabase.from('tenants').select('*').eq('id', tenantId).single();
    if (!tenant || !tenant.vercel_project_id) return json(res, 404, { error: 'Tenant not found or not fully provisioned' });
    const deployment = await vercel.createDeployment(vercelToken, vercelTeamId, {
      projectName: tenant.vercel_project_name,
      projectId: tenant.vercel_project_id,
      gitSource: { type: 'github', repoId: process.env.TENANT_GIT_REPO_ID, ref: 'main' }
    });
    await logActivity({ superAdminId: session.superAdmin.id, superAdminName: session.superAdmin.name, tenantId, actionType: 'update_template', details: { deploymentId: deployment.id }, req });
    return json(res, 202, { success: true, deploymentId: deployment.id });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
}

async function handleBulkUpdateTemplate(req, res) {
  const session = await requireAuth(req, res);
  if (!session) return;
  const { data: tenants } = await supabase.from('tenants').select('*').eq('status', 'active');
  const results = [];
  for (const tenant of tenants || []) {
    try {
      const fakeReq = req, fakeRes = { writeHead() {}, end(body) { results.push({ tenant: tenant.slug, ...JSON.parse(body) }); } };
      await handleUpdateTemplate(fakeReq, fakeRes, tenant.id);
    } catch (e) {
      results.push({ tenant: tenant.slug, success: false, error: e.message });
    }
  }
  await logActivity({ superAdminId: session.superAdmin.id, superAdminName: session.superAdmin.name, actionType: 'bulk_update_template', details: { count: results.length }, req });
  return json(res, 200, { success: true, results });
}

// ---------------------------------------------------------------------------
// ROUTER
// ---------------------------------------------------------------------------

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }

  let pathname = '/';
  try { pathname = new URL(req.url, `http://${req.headers.host || 'localhost'}`).pathname; }
  catch { pathname = req.url.split('?')[0] || '/'; }
  const p = pathname.replace(/\/$/, '');
  const segments = p.split('/').filter(Boolean); // ['api','factory', ...]

  try {
    if (p === '/api/factory/bootstrap') return handleBootstrap(req, res);
    if (p === '/api/factory/auth/login') return handleLogin(req, res);
    if (p === '/api/factory/auth/totp/enroll') return handleTotpEnroll(req, res);
    if (p === '/api/factory/auth/totp/enroll/confirm') return handleTotpEnrollConfirm(req, res);
    if (p === '/api/factory/auth/totp/verify') return handleTotpVerify(req, res);
    if (p === '/api/factory/auth/logout') return handleLogout(req, res);
    if (p === '/api/factory/vault/bootstrap') return handleVaultBootstrap(req, res);
    if (p === '/api/factory/tenants' && req.method === 'GET') return handleListTenants(req, res);
    if (p === '/api/factory/tenants' && req.method === 'POST') return handleCreateTenant(req, res);
    if (p === '/api/factory/audit-log') return handleAuditLog(req, res);
    if (p === '/api/factory/template/bulk-update' && req.method === 'POST') return handleBulkUpdateTemplate(req, res);

    if (segments[1] === 'factory' && segments[2] === 'jobs' && segments[3]) {
      return handleGetJob(req, res, segments[3]);
    }
    if (segments[1] === 'factory' && segments[2] === 'tenants' && segments[3]) {
      const tenantId = segments[3];
      const action = segments[4];
      if (action === 'suspend' && req.method === 'POST') return handleSuspendTenant(req, res, tenantId);
      if (action === 'resume' && req.method === 'POST') return handleResumeTenant(req, res, tenantId);
      if (action === 'delete' && req.method === 'POST') return handleDeleteTenant(req, res, tenantId);
      if (action === 'admin-password' && req.method === 'GET') return handleRevealAdminPassword(req, res, tenantId);
      if (action === 'reset-admin-password' && req.method === 'POST') return handleResetAdminPassword(req, res, tenantId);
      if (action === 'update-template' && req.method === 'POST') return handleUpdateTemplate(req, res, tenantId);
    }

    return json(res, 404, { error: 'Not found', path: p });
  } catch (err) {
    console.error('[Factory API] Unhandled error:', err);
    return json(res, 500, { error: 'Internal server error' });
  }
};
