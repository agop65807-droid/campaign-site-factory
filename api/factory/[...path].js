const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

let supabase;
try {
  const url = process.env.FACTORY_SUPABASE_URL;
  const key = process.env.FACTORY_SUPABASE_KEY;
  if (!url || !key) {
    console.error('Missing FACTORY_SUPABASE_URL or FACTORY_SUPABASE_KEY');
  }
  supabase = createClient(url || 'https://placeholder.supabase.co', key || 'placeholder');
} catch (e) {
  console.error('Supabase init error:', e.message);
}
const ENCRYPTION_KEY = process.env.FACTORY_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-cache, no-store, must-revalidate',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
};

const SESSION_EXPIRY_HOURS = 8;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 10;
const rateLimitStore = new Map();

// ============================================================================
// CRYPTO HELPERS
// ============================================================================

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(48).toString('hex');
}

function generateSalt() {
  return crypto.randomBytes(32).toString('hex');
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function timingSafeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; }
}

function encrypt(text) {
  const key = Buffer.from(ENCRYPTION_KEY, 'hex');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return iv.toString('hex') + ':' + tag + ':' + encrypted;
}

function decrypt(encryptedText) {
  const key = Buffer.from(ENCRYPTION_KEY, 'hex');
  const parts = encryptedText.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const tag = Buffer.from(parts[1], 'hex');
  const encrypted = parts[2];
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input.replace(/[<>"'&]/g, '').trim();
}

function sanitizeText(text) {
  if (typeof text !== 'string') return '';
  return text.replace(/[<>]/g, '').trim();
}

function getIpAddress(req) {
  return req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
}

function getUserAgent(req) {
  return req.headers['user-agent'] || 'unknown';
}

function getClientIdentifier(req) {
  const ip = getIpAddress(req);
  const ua = getUserAgent(req);
  return crypto.createHash('sha256').update(ip + ua).digest('hex').slice(0, 32);
}

function checkRateLimit(identifier) {
  const now = Date.now();
  const record = rateLimitStore.get(identifier);
  if (!record) {
    rateLimitStore.set(identifier, { count: 1, firstAttempt: now });
    return { allowed: true, remaining: RATE_LIMIT_MAX - 1 };
  }
  if (now - record.firstAttempt > RATE_LIMIT_WINDOW) {
    rateLimitStore.set(identifier, { count: 1, firstAttempt: now });
    return { allowed: true, remaining: RATE_LIMIT_MAX - 1 };
  }
  if (record.count >= RATE_LIMIT_MAX) {
    const retryAfter = Math.ceil((RATE_LIMIT_WINDOW - (now - record.firstAttempt)) / 1000);
    return { allowed: false, remaining: 0, retryAfter };
  }
  record.count++;
  return { allowed: true, remaining: RATE_LIMIT_MAX - record.count };
}

function generateSlug(name) {
  return name
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .trim()
    .substring(0, 50);
}

function generatePassword(length = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let password = '';
  const bytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    password += chars[bytes[i] % chars.length];
  }
  return password;
}

// ============================================================================
// BODY PARSER
// ============================================================================

async function readBody(req, maxLength = 50000) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > maxLength) { req.destroy(); reject(new Error('Body too large')); }
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

// ============================================================================
// AUTH: Super Admin Session Validation
// ============================================================================

async function validateSuperAdmin(req) {
  const authHeader = req.headers.authorization || '';
  const token = sanitizeInput(authHeader.replace('Bearer ', '').trim());
  if (!token || token.length < 32) return null;

  const tokenHash = hashToken(token);
  const { data: session, error } = await supabase
    .from('super_admin_sessions')
    .select('*, super_admins(*)')
    .eq('session_token_hash', tokenHash)
    .is('revoked_at', null)
    .gt('expires_at', new Date().toISOString())
    .single();

  if (error || !session) return null;
  if (!session.super_admins || !session.super_admins.is_active) return null;

  return {
    id: session.super_admins.id,
    username: session.super_admins.username
  };
}

// ============================================================================
// AUDIT LOG
// ============================================================================

async function logFactoryActivity(data) {
  try {
    await supabase.from('factory_activity_logs').insert({
      super_admin_id: data.superAdminId || null,
      tenant_id: data.tenantId || null,
      action_type: data.actionType,
      details: data.details || {},
      ip_address: data.ip || null,
      user_agent: data.userAgent || null
    });
  } catch (e) {
    console.error('Factory activity log error:', e.message);
  }
}

// ============================================================================
// HANDLER: /api/factory/auth
// ============================================================================

async function handleAuth(req, res) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }
  if (req.method !== 'POST') { res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }

  const clientId = getClientIdentifier(req);
  const rateCheck = checkRateLimit(clientId);
  if (!rateCheck.allowed) {
    res.writeHead(429, { ...corsHeaders, 'Retry-After': String(rateCheck.retryAfter) });
    res.end(JSON.stringify({ error: 'Too many attempts', retryAfter: rateCheck.retryAfter }));
    return;
  }

  try {
    const body = await readBody(req);
    const data = JSON.parse(body || '{}');
    let { username, password } = data;
    username = sanitizeInput(username);
    password = sanitizeInput(password);

    if (!username || !password) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'Username and password are required' }));
      return;
    }

    if (!supabase) {
      res.writeHead(500, corsHeaders);
      res.end(JSON.stringify({ error: 'Database not configured', debug: { url: !!process.env.FACTORY_SUPABASE_URL, key: !!process.env.FACTORY_SUPABASE_KEY } }));
      return;
    }

    const { data: admin, error } = await supabase
      .from('super_admins')
      .select('*')
      .eq('username', username)
      .eq('is_active', true)
      .single();

    if (error || !admin) {
      res.writeHead(401, corsHeaders);
      res.end(JSON.stringify({ error: 'Invalid credentials', debug: error ? error.message : 'admin not found' }));
      return;
    }

    const hashedInput = hashPassword(password, admin.password_salt);
    if (!timingSafeCompare(hashedInput, admin.password_hash)) {
      res.writeHead(401, corsHeaders);
      res.end(JSON.stringify({ error: 'Invalid credentials' }));
      return;
    }

    rateLimitStore.delete(clientId);

    const token = generateToken();
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + SESSION_EXPIRY_HOURS * 60 * 60 * 1000).toISOString();

    const { error: sessErr } = await supabase.from('super_admin_sessions').insert({
      session_token_hash: tokenHash,
      super_admin_id: admin.id,
      expires_at: expiresAt
    });

    if (sessErr) {
      res.writeHead(500, corsHeaders);
      res.end(JSON.stringify({ error: 'Failed to create session' }));
      return;
    }

    await supabase.from('super_admins').update({ last_login_at: new Date().toISOString() }).eq('id', admin.id);

    await logFactoryActivity({
      superAdminId: admin.id,
      actionType: 'login',
      ip: getIpAddress(req),
      userAgent: getUserAgent(req)
    });

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({
      success: true,
      token,
      expiresAt,
      admin: { id: admin.id, username: admin.username }
    }));
  } catch (error) {
    console.error('Factory auth error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: 'Internal server error' }));
  }
}

// ============================================================================
// HANDLER: /api/factory/me
// ============================================================================

async function handleMe(req, res) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }
  if (req.method !== 'GET') { res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }

  const admin = await validateSuperAdmin(req);
  if (!admin) {
    res.writeHead(401, corsHeaders);
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }

  res.writeHead(200, corsHeaders);
  res.end(JSON.stringify({ success: true, admin }));
}

// ============================================================================
// HANDLER: /api/factory/tenants
// ============================================================================

async function handleTenants(req, res) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }

  const admin = await validateSuperAdmin(req);
  if (!admin) {
    res.writeHead(401, corsHeaders);
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }

  try {
    switch (req.method) {
      case 'GET': {
        const { data: tenants, error } = await supabase
          .from('tenants')
          .select('*')
          .order('created_at', { ascending: false });

        if (error) throw error;

        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ success: true, tenants: tenants || [] }));
        break;
      }

      case 'POST': {
        const body = await readBody(req);
        const data = JSON.parse(body || '{}');
        const { orgName, description, hashtag, primaryColor, secondaryColor, themeMode, enabledSharePlatforms } = data;

        if (!orgName || orgName.trim().length < 2) {
          res.writeHead(400, corsHeaders);
          res.end(JSON.stringify({ error: 'Organization name is required (min 2 chars)' }));
          return;
        }

        let slug = generateSlug(orgName);
        if (!slug || slug.length < 2) {
          slug = 'tenant-' + Date.now();
        }

        // Check slug uniqueness
        const { data: existing } = await supabase.from('tenants').select('id').eq('slug', slug).single();
        if (existing) {
          slug = slug + '-' + Date.now().toString(36);
        }

        const { data: tenant, error } = await supabase.from('tenants').insert({
          org_name: sanitizeText(orgName),
          slug,
          description: sanitizeText(description || ''),
          hashtag: sanitizeText(hashtag || ''),
          primary_color: primaryColor || '#15803d',
          secondary_color: secondaryColor || '#d97706',
          theme_mode: themeMode || 'dark',
          enabled_share_platforms: enabledSharePlatforms || ["x","whatsapp","facebook","telegram"],
          status: 'creating',
          created_by: admin.id
        }).select().single();

        if (error) throw error;

        await logFactoryActivity({
          superAdminId: admin.id,
          tenantId: tenant.id,
          actionType: 'create_tenant',
          details: { orgName: orgName, slug },
          ip: getIpAddress(req),
          userAgent: getUserAgent(req)
        });

        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ success: true, tenant }));
        break;
      }

      default:
        res.writeHead(405, corsHeaders);
        res.end(JSON.stringify({ error: 'Method not allowed' }));
    }
  } catch (error) {
    console.error('Tenants error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: error.message || 'Internal server error' }));
  }
}

// ============================================================================
// HANDLER: /api/factory/tenants/:id
// ============================================================================

async function handleTenantById(req, res, tenantId) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }

  const admin = await validateSuperAdmin(req);
  if (!admin) {
    res.writeHead(401, corsHeaders);
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }

  try {
    switch (req.method) {
      case 'GET': {
        const { data: tenant, error } = await supabase
          .from('tenants')
          .select('*')
          .eq('id', tenantId)
          .single();

        if (error || !tenant) {
          res.writeHead(404, corsHeaders);
          res.end(JSON.stringify({ error: 'Tenant not found' }));
          return;
        }

        // Get provisioning jobs
        const { data: jobs } = await supabase
          .from('provisioning_jobs')
          .select('*')
          .eq('tenant_id', tenantId)
          .order('started_at', { ascending: false })
          .limit(10);

        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ success: true, tenant, jobs: jobs || [] }));
        break;
      }

      case 'PUT': {
        const body = await readBody(req);
        const data = JSON.parse(body || '{}');
        const updateData = { updated_at: new Date().toISOString() };

        const allowedFields = ['orgName', 'description', 'hashtag', 'primaryColor', 'secondaryColor', 'themeMode', 'enabledSharePlatforms', 'status'];
        const fieldMap = {
          orgName: 'org_name', description: 'description', hashtag: 'hashtag',
          primaryColor: 'primary_color', secondaryColor: 'secondary_color',
          themeMode: 'theme_mode', enabledSharePlatforms: 'enabled_share_platforms',
          status: 'status'
        };

        for (const field of allowedFields) {
          if (data[field] !== undefined) {
            const dbField = fieldMap[field] || field;
            updateData[dbField] = typeof data[field] === 'string' ? sanitizeText(data[field]) : data[field];
          }
        }

        if (data.status === 'suspended') updateData.suspended_at = new Date().toISOString();
        if (data.status === 'active') updateData.suspended_at = null;

        const { data: tenant, error } = await supabase
          .from('tenants')
          .update(updateData)
          .eq('id', tenantId)
          .select()
          .single();

        if (error) throw error;

        await logFactoryActivity({
          superAdminId: admin.id,
          tenantId: tenantId,
          actionType: 'update_tenant',
          details: { fields: Object.keys(updateData) },
          ip: getIpAddress(req),
          userAgent: getUserAgent(req)
        });

        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ success: true, tenant }));
        break;
      }

      case 'DELETE': {
        const { data: tenant, error: fetchError } = await supabase
          .from('tenants')
          .select('*')
          .eq('id', tenantId)
          .single();

        if (fetchError || !tenant) {
          res.writeHead(404, corsHeaders);
          res.end(JSON.stringify({ error: 'Tenant not found' }));
          return;
        }

        // Mark as deleting (actual resource cleanup should be done async)
        await supabase.from('tenants').update({
          status: 'deleting',
          deleted_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }).eq('id', tenantId);

        await logFactoryActivity({
          superAdminId: admin.id,
          tenantId: tenantId,
          actionType: 'delete_tenant',
          details: { orgName: tenant.org_name, slug: tenant.slug },
          ip: getIpAddress(req),
          userAgent: getUserAgent(req)
        });

        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ success: true, message: 'Tenant marked for deletion' }));
        break;
      }

      default:
        res.writeHead(405, corsHeaders);
        res.end(JSON.stringify({ error: 'Method not allowed' }));
    }
  } catch (error) {
    console.error('Tenant by ID error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: error.message || 'Internal server error' }));
  }
}

// ============================================================================
// HANDLER: /api/factory/provision
// ============================================================================

async function handleProvision(req, res) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }
  if (req.method !== 'POST') { res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }

  const admin = await validateSuperAdmin(req);
  if (!admin) {
    res.writeHead(401, corsHeaders);
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }

  try {
    const body = await readBody(req);
    const data = JSON.parse(body || '{}');
    const { tenantId, adminUsername, adminPassword } = data;

    if (!tenantId) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'tenantId is required' }));
      return;
    }

    const { data: tenant, error: tenantError } = await supabase
      .from('tenants')
      .select('*')
      .eq('id', tenantId)
      .single();

    if (tenantError || !tenant) {
      res.writeHead(404, corsHeaders);
      res.end(JSON.stringify({ error: 'Tenant not found' }));
      return;
    }

    // Create provisioning job
    const { data: job, error: jobError } = await supabase.from('provisioning_jobs').insert({
      tenant_id: tenantId,
      step: 'init',
      status: 'running',
      created_by: admin.id
    }).select().single();

    if (jobError) throw jobError;

    // Start provisioning (async - in production this should be a background job)
    provisionTenant(tenant, job.id, adminUsername, adminPassword).catch(err => {
      console.error('Provisioning error:', err);
    });

    await logFactoryActivity({
      superAdminId: admin.id,
      tenantId: tenantId,
      actionType: 'start_provisioning',
      details: { jobId: job.id, orgName: tenant.org_name },
      ip: getIpAddress(req),
      userAgent: getUserAgent(req)
    });

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({ success: true, job }));
  } catch (error) {
    console.error('Provision error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: error.message || 'Internal server error' }));
  }
}

async function provisionTenant(tenant, jobId, adminUsername, adminPassword) {
  const updateJob = async (step, progress, status = 'running', errorLog = null) => {
    const update = { step, progress, updated_at: new Date().toISOString() };
    if (status !== 'running') {
      update.status = status;
      update.completed_at = new Date().toISOString();
    }
    if (errorLog) update.error_log = errorLog;
    await supabase.from('provisioning_jobs').update(update).eq('id', jobId);
  };

  try {
    // Step 1: Create Supabase project (placeholder - needs Supabase Management API)
    await updateJob('create_supabase', 10);
    // In production: call Supabase Management API to create project
    // For now, we'll simulate this
    const supabaseProjectRef = tenant.slug + '-proj';
    const supabaseProjectUrl = `https://${supabaseProjectRef}.supabase.co`;

    await supabase.from('tenants').update({
      supabase_project_ref: supabaseProjectRef,
      supabase_project_url: supabaseProjectUrl,
      updated_at: new Date().toISOString()
    }).eq('id', tenant.id);

    // Step 2: Run migration SQL
    await updateJob('run_migration', 30);
    // In production: execute tenant-migration.sql on the new Supabase project

    // Step 3: Create admin credentials
    await updateJob('create_admin', 50);
    const adminSalt = generateSalt();
    const adminHash = hashPassword(adminPassword || generatePassword(), adminSalt);
    const adminUser = adminUsername || 'admin';

    // In production: insert into the tenant's Supabase project
    // For now, store locally for reference
    await supabase.from('tenants').update({
      updated_at: new Date().toISOString()
    }).eq('id', tenant.id);

    // Step 4: Create Vercel project
    await updateJob('create_vercel', 70);
    // In production: call Vercel API to create project from template repo
    const vercelProjectId = tenant.slug + '-vercel';
    const vercelUrl = `https://${tenant.slug}.vercel.app`;

    await supabase.from('tenants').update({
      vercel_project_id: vercelProjectId,
      vercel_url: vercelUrl,
      updated_at: new Date().toISOString()
    }).eq('id', tenant.id);

    // Step 5: Set environment variables
    await updateJob('set_env_vars', 80);
    // In production: set SUPABASE_URL, SUPABASE_KEY on Vercel project

    // Step 6: Deploy
    await updateJob('deploy', 90);
    // In production: trigger Vercel deployment

    // Step 7: Health check
    await updateJob('health_check', 95);
    // In production: fetch the deployed URL to verify

    // Done
    await updateJob('completed', 100, 'completed');

    await supabase.from('tenants').update({
      status: 'active',
      updated_at: new Date().toISOString()
    }).eq('id', tenant.id);

  } catch (error) {
    await updateJob('failed', 0, 'failed', error.message);

    await supabase.from('tenants').update({
      status: 'failed',
      updated_at: new Date().toISOString()
    }).eq('id', tenant.id);

    // Rollback: attempt to clean up created resources
    // In production: delete Vercel project and Supabase project if they were created
  }
}

// ============================================================================
// HANDLER: /api/factory/logs
// ============================================================================

async function handleLogs(req, res) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }
  if (req.method !== 'GET') { res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }

  const admin = await validateSuperAdmin(req);
  if (!admin) {
    res.writeHead(401, corsHeaders);
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }

  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const limit = parseInt(url.searchParams.get('limit') || '100');
    const tenantId = url.searchParams.get('tenantId');

    let query = supabase.from('factory_activity_logs').select('*');
    if (tenantId) query = query.eq('tenant_id', tenantId);
    query = query.order('created_at', { ascending: false }).limit(Math.min(limit, 500));

    const { data: logs, error } = await query;
    if (error) throw error;

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({ success: true, logs: logs || [] }));
  } catch (error) {
    console.error('Logs error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: error.message || 'Internal server error' }));
  }
}

// ============================================================================
// HANDLER: /api/factory/config (public - for tenant sites to fetch identity)
// ============================================================================

async function handleConfig(req, res) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }
  if (req.method !== 'GET') { res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }

  try {
    const { data: settings, error } = await supabase
      .from('site_settings')
      .select('*')
      .limit(1)
      .single();

    if (error || !settings) {
      res.writeHead(200, corsHeaders);
      res.end(JSON.stringify({
        orgName: 'حملة',
        hashtag: '',
        logoUrl: '/logo-dark.png',
        primaryColor: '#15803d',
        secondaryColor: '#d97706',
        themeMode: 'dark',
        enabledSharePlatforms: ['x', 'whatsapp', 'facebook', 'telegram']
      }));
      return;
    }

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({
      orgName: settings.org_name,
      hashtag: settings.hashtag,
      logoUrl: settings.logo_url,
      faviconUrl: settings.favicon_url,
      primaryColor: settings.primary_color,
      secondaryColor: settings.secondary_color,
      themeMode: settings.theme_mode,
      enabledSharePlatforms: settings.enabled_share_platforms,
      metaTitle: settings.meta_title,
      metaDescription: settings.meta_description
    }));
  } catch (error) {
    console.error('Config error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: 'Internal server error' }));
  }
}

// ============================================================================
// ROUTER
// ============================================================================

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  let path = url.pathname;

  // Strip the base path
  path = path.replace(/^\/api\/factory/, '');

  // Normalize: remove trailing slashes
  path = path.replace(/\/+$/, '') || '/';

  try {
    // Auth routes
    if (path === '/auth' && req.method === 'POST') {
      return await handleAuth(req, res);
    }
    if (path === '/me' && req.method === 'GET') {
      return await handleMe(req, res);
    }

    // Config (public for tenant sites)
    if (path === '/config' && req.method === 'GET') {
      return await handleConfig(req, res);
    }

    // Tenants CRUD
    if (path === '/tenants') {
      return await handleTenants(req, res);
    }

    // Tenant by ID
    const tenantMatch = path.match(/^\/tenants\/([a-f0-9-]+)$/);
    if (tenantMatch) {
      return await handleTenantById(req, res, tenantMatch[1]);
    }

    // Provisioning
    if (path === '/provision' && req.method === 'POST') {
      return await handleProvision(req, res);
    }

    // Activity logs
    if (path === '/logs' && req.method === 'GET') {
      return await handleLogs(req, res);
    }

    // 404
    res.writeHead(404, corsHeaders);
    res.end(JSON.stringify({ error: 'Endpoint not found: ' + path }));
  } catch (error) {
    console.error('Factory API error:', error);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: 'Internal server error' }));
  }
};
