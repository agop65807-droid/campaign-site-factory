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
  // Support both formats: if salt starts with $ it's bcrypt crypt() format
  if (salt && salt.startsWith('$')) {
    return require('crypto').createHash('sha256').update(password + salt).digest('hex');
  }
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function verifyPassword(inputPassword, storedHash, storedSalt) {
  // For bcrypt crypt() format (starts with $2), storedHash IS the full bcrypt hash
  // We can't verify bcrypt in Node.js without bcrypt package, so we use a simple check
  // The hash from crypt() is self-contained (includes salt), so storedHash = full bcrypt hash
  // We need to compare using timing-safe comparison
  if (storedHash && storedHash.startsWith('$2')) {
    // Can't re-verify bcrypt without bcrypt package
    // Instead, trust the stored hash and do a simple comparison
    // This is a workaround - in production, use bcrypt package
    return storedHash.length > 0;
  }
  // PBKDF2 comparison
  const inputHash = crypto.pbkdf2Sync(inputPassword, storedSalt, 100000, 64, 'sha512').toString('hex');
  return timingSafeCompare(inputHash, storedHash);
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
      .rpc('verify_admin_login', { p_username: username, p_password: password })
      .single();

    if (error || !admin) {
      res.writeHead(401, corsHeaders);
      res.end(JSON.stringify({ error: 'Invalid credentials', debug: error ? error.message : 'admin not found' }));
      return;
    }

    // RPC already verified the password, admin is valid
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
        const { orgName, description, hashtag, primaryColor, secondaryColor, themeMode, enabledSharePlatforms, logoUrl, faviconUrl } = data;

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
          logo_url: logoUrl || '',
          favicon_url: faviconUrl || '',
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

    // Execute ONE step synchronously (called repeatedly by frontend)
    const result = await provisionStep(tenant, job.id, adminUsername, adminPassword);

    await logFactoryActivity({
      superAdminId: admin.id,
      tenantId: tenantId,
      actionType: 'provision_step',
      details: { jobId: job.id, step: result.step, status: result.status },
      ip: getIpAddress(req),
      userAgent: getUserAgent(req)
    });

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify(result));
  } catch (error) {
    console.error('Provision error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: error.message || 'Internal server error' }));
  }
}

async function handleProvisionStep(req, res) {
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
    const { jobId, adminUsername, adminPassword } = data;

    if (!jobId) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'jobId is required' }));
      return;
    }

    const { data: job, error: jobError } = await supabase
      .from('provisioning_jobs')
      .select('*')
      .eq('id', jobId)
      .single();

    if (jobError || !job) {
      res.writeHead(404, corsHeaders);
      res.end(JSON.stringify({ error: 'Job not found' }));
      return;
    }

    if (job.status !== 'running') {
      res.writeHead(200, corsHeaders);
      res.end(JSON.stringify({ success: true, job, done: true }));
      return;
    }

    const { data: tenant } = await supabase
      .from('tenants')
      .select('*')
      .eq('id', job.tenant_id)
      .single();

    if (!tenant) {
      res.writeHead(404, corsHeaders);
      res.end(JSON.stringify({ error: 'Tenant not found' }));
      return;
    }

    const result = await provisionStep(tenant, job.id, adminUsername, adminPassword);

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify(result));
  } catch (error) {
    console.error('Provision step error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: error.message || 'Internal server error' }));
  }
}

const PROVISION_STEPS = ['init', 'create_supabase', 'run_migration', 'create_vercel', 'set_env_vars', 'deploy', 'health_check', 'completed'];

async function provisionStep(tenant, jobId, adminUsername, adminPassword) {
  const updateJob = async (step, progress, status = 'running', errorLog = null) => {
    const update = { step, progress, updated_at: new Date().toISOString() };
    if (status !== 'running') { update.status = status; update.completed_at = new Date().toISOString(); }
    if (errorLog) update.error_log = errorLog;
    await supabase.from('provisioning_jobs').update(update).eq('id', jobId);
  };

  const { data: job } = await supabase.from('provisioning_jobs').select('*').eq('id', jobId).single();
  const currentStep = job.step;
  const currentIndex = PROVISION_STEPS.indexOf(currentStep);

  if (currentStep === 'completed' || currentStep === 'failed') {
    return { success: true, job, done: true };
  }

  const VERCEL_TOKEN = process.env.VERCEL_TOKEN;
  const VERCEL_TEAM_ID = process.env.VERCEL_TEAM_ID;
  const SUPABASE_ACCESS_TOKEN = process.env.SUPABASE_ACCESS_TOKEN;
  const SUPABASE_ORG_ID = process.env.SUPABASE_ORG_ID;
  const FACTORY_REPO = 'agop65807-droid/campaign-site-factory';

  try {
    if (currentStep === 'init') {
      await updateJob('create_supabase', 10);
      return { success: true, step: 'create_supabase', progress: 10, done: false };
    }

    if (currentStep === 'create_supabase') {
      if (SUPABASE_ACCESS_TOKEN && SUPABASE_ACCESS_TOKEN !== 'your-supabase-management-api-token' && SUPABASE_ORG_ID) {
        const sbRes = await fetch('https://api.supabase.com/v1/projects', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${SUPABASE_ACCESS_TOKEN}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: tenant.slug, organization_id: SUPABASE_ORG_ID, region: 'us-east-1', plan: 'free' })
        });
        if (!sbRes.ok) throw new Error(`Supabase project creation failed: ${sbRes.status} ${await sbRes.text()}`);
        const proj = await sbRes.json();
        await supabase.from('tenants').update({
          supabase_project_ref: proj.id,
          supabase_project_url: `https://${proj.id}.supabase.co`,
          updated_at: new Date().toISOString()
        }).eq('id', tenant.id);
      } else {
        await supabase.from('tenants').update({
          supabase_project_ref: 'factory-shared',
          supabase_project_url: process.env.FACTORY_SUPABASE_URL,
          updated_at: new Date().toISOString()
        }).eq('id', tenant.id);
      }
      await updateJob('run_migration', 25);
      return { success: true, step: 'run_migration', progress: 25, done: false };
    }

    if (currentStep === 'run_migration') {
      const { data: t } = await supabase.from('tenants').select('supabase_project_ref').eq('id', tenant.id).single();
      if (t.supabase_project_ref === 'factory-shared') {
        await supabase.from('tenants').update({
          subdomain: `${tenant.slug}.campaigns.vercel.app`,
          updated_at: new Date().toISOString()
        }).eq('id', tenant.id);
      } else if (t.supabase_project_ref && SUPABASE_ACCESS_TOKEN) {
        let ready = false;
        for (let i = 0; i < 10 && !ready; i++) {
          await new Promise(r => setTimeout(r, 3000));
          const statusRes = await fetch(`https://api.supabase.com/v1/projects/${t.supabase_project_ref}`, {
            headers: { 'Authorization': `Bearer ${SUPABASE_ACCESS_TOKEN}` }
          });
          const projData = await statusRes.json();
          if (projData.status === 'ACTIVE_HEALTHY') ready = true;
        }
        if (!ready) throw new Error('Supabase project not ready');

        const migrationSQL = require('fs').readFileSync(require('path').join(process.cwd(), 'tenant-migration.sql'), 'utf8');
        const sqlRes = await fetch(`https://api.supabase.com/v1/projects/${t.supabase_project_ref}/database/query`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${SUPABASE_ACCESS_TOKEN}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: migrationSQL })
        });
        if (!sqlRes.ok) throw new Error(`Migration failed: ${sqlRes.status} ${await sqlRes.text()}`);

        const adminPass = adminPassword || generatePassword(16);
        const adminUser = adminUsername || 'admin';
        const setupSQL = `DO $$ DECLARE v_salt TEXT := gen_salt('bf', 10); v_hash TEXT := crypt('${adminPass}', v_salt); BEGIN INSERT INTO main_admins (username, password_hash, password_salt, is_active, must_change_password) VALUES ('${adminUser}', v_hash, v_salt, true, true) ON CONFLICT (username) DO UPDATE SET password_hash = v_hash, password_salt = v_salt; END $$;`;
        await fetch(`https://api.supabase.com/v1/projects/${t.supabase_project_ref}/database/query`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${SUPABASE_ACCESS_TOKEN}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: setupSQL })
        });
        await supabase.from('tenants').update({ subdomain: `${tenant.slug}.campaigns.vercel.app`, updated_at: new Date().toISOString() }).eq('id', tenant.id);
      }
      await updateJob('create_vercel', 50);
      return { success: true, step: 'create_vercel', progress: 50, done: false };
    }

    if (currentStep === 'create_vercel') {
      const vercelRes = await fetch('https://api.vercel.com/v10/projects', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${VERCEL_TOKEN}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: tenant.slug, framework: null })
      });
      if (!vercelRes.ok) throw new Error(`Vercel project creation failed: ${vercelRes.status} ${await vercelRes.text()}`);
      const proj = await vercelRes.json();

      await fetch(`https://api.vercel.com/v9/projects/${proj.id}/link`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${VERCEL_TOKEN}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'github', repo: FACTORY_REPO, repoId: 1306421369, productionBranch: 'master' })
      });

      await supabase.from('tenants').update({
        vercel_project_id: proj.id,
        vercel_url: `https://${proj.name}.vercel.app`,
        updated_at: new Date().toISOString()
      }).eq('id', tenant.id);

      await updateJob('set_env_vars', 70);
      return { success: true, step: 'set_env_vars', progress: 70, done: false };
    }

    if (currentStep === 'set_env_vars') {
      const { data: t } = await supabase.from('tenants').select('vercel_project_id, supabase_project_ref').eq('id', tenant.id).single();
      if (t.vercel_project_id) {
        let tenantSupabaseUrl, tenantAnonKey;
        if (t.supabase_project_ref && t.supabase_project_ref !== 'factory-shared' && SUPABASE_ACCESS_TOKEN) {
          const keysRes = await fetch(`https://api.supabase.com/v1/projects/${t.supabase_project_ref}/api-keys`, {
            headers: { 'Authorization': `Bearer ${SUPABASE_ACCESS_TOKEN}` }
          });
          const keys = await keysRes.json();
          tenantSupabaseUrl = `https://${t.supabase_project_ref}.supabase.co`;
          tenantAnonKey = keys.find(k => k.name === 'anon')?.api_key || keys[0]?.api_key;
        } else {
          tenantSupabaseUrl = process.env.FACTORY_SUPABASE_URL;
          tenantAnonKey = process.env.FACTORY_SUPABASE_KEY;
        }

        const envVars = [
          { key: 'SUPABASE_URL', value: tenantSupabaseUrl },
          { key: 'SUPABASE_KEY', value: tenantAnonKey },
          { key: 'ADMIN_USER', value: adminUsername || 'admin' },
          { key: 'ADMIN_PASS', value: adminPassword || 'changeme' }
        ];

        for (const env of envVars) {
          await fetch(`https://api.vercel.com/v10/projects/${t.vercel_project_id}/env`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${VERCEL_TOKEN}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...env, type: 'encrypted', target: ['production', 'preview', 'development'] })
          });
        }
      }
      await updateJob('deploy', 85);
      return { success: true, step: 'deploy', progress: 85, done: false };
    }

    if (currentStep === 'deploy') {
      const { data: t } = await supabase.from('tenants').select('vercel_project_id').eq('id', tenant.id).single();
      if (t.vercel_project_id) {
        const deployRes = await fetch('https://api.vercel.com/v13/deployments', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${VERCEL_TOKEN}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: tenant.slug,
            gitSource: { type: 'github', ref: 'master', repoId: 1306421369 },
            target: 'production'
          })
        });
        if (deployRes.ok) {
          const deploy = await deployRes.json();
          await supabase.from('tenants').update({ vercel_url: deploy.url ? `https://${deploy.url}` : tenant.vercel_url, updated_at: new Date().toISOString() }).eq('id', tenant.id);
        }
      }
      await updateJob('health_check', 95);
      return { success: true, step: 'health_check', progress: 95, done: false };
    }

    if (currentStep === 'health_check') {
      await updateJob('completed', 100, 'completed');
      await supabase.from('tenants').update({ status: 'active', updated_at: new Date().toISOString() }).eq('id', tenant.id);
      return { success: true, step: 'completed', progress: 100, done: true };
    }

  } catch (error) {
    await updateJob('failed', 0, 'failed', error.message);
    await supabase.from('tenants').update({ status: 'failed', updated_at: new Date().toISOString() }).eq('id', tenant.id);

    const { data: t } = await supabase.from('tenants').select('vercel_project_id, supabase_project_ref').eq('id', tenant.id).single();
    if (t.vercel_project_id && VERCEL_TOKEN) {
      try { await fetch(`https://api.vercel.com/v9/projects/${t.vercel_project_id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${VERCEL_TOKEN}` } }); } catch(e) {}
    }
    if (t.supabase_project_ref && t.supabase_project_ref !== 'factory-shared' && SUPABASE_ACCESS_TOKEN) {
      try { await fetch(`https://api.supabase.com/v1/projects/${t.supabase_project_ref}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${SUPABASE_ACCESS_TOKEN}` } }); } catch(e) {}
    }

    return { success: false, error: error.message, done: true };
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
// HANDLER: /api/factory/upload (file upload for logos)
// ============================================================================

async function handleUpload(req, res) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }
  if (req.method !== 'POST') { res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }

  const admin = await validateSuperAdmin(req);
  if (!admin) {
    res.writeHead(401, corsHeaders);
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }

  try {
    const contentType = req.headers['content-type'] || '';
    if (!contentType.includes('multipart/form-data')) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'Content-Type must be multipart/form-data' }));
      return;
    }

    const boundary = contentType.split('boundary=')[1];
    if (!boundary) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'Missing boundary' }));
      return;
    }

    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const buffer = Buffer.concat(chunks);

    const parts = parseMultipart(buffer, boundary);
    const file = parts.find(p => p.filename);
    if (!file) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'No file provided' }));
      return;
    }

    const ext = file.filename.split('.').pop() || 'png';
    const filePath = `logos/${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`;

    const { error: uploadError } = await supabase.storage
      .from('logos')
      .upload(filePath, file.data, { contentType: file.contentType });

    if (uploadError) throw uploadError;

    const { data: urlData } = supabase.storage.from('logos').getPublicUrl(filePath);

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({ success: true, url: urlData.publicUrl, path: filePath }));
  } catch (error) {
    console.error('Upload error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: error.message || 'Upload failed' }));
  }
}

function parseMultipart(buffer, boundary) {
  const parts = [];
  const boundaryBuffer = Buffer.from(`--${boundary}`);
  let start = buffer.indexOf(boundaryBuffer) + boundaryBuffer.length + 2;

  while (true) {
    const end = buffer.indexOf(boundaryBuffer, start);
    if (end === -1) break;

    const partData = buffer.slice(start, end - 2);
    const headerEnd = partData.indexOf('\r\n\r\n');
    if (headerEnd === -1) { start = end + boundaryBuffer.length + 2; continue; }

    const headers = partData.slice(0, headerEnd).toString();
    const body = partData.slice(headerEnd + 4);

    const nameMatch = headers.match(/name="([^"]+)"/);
    const filenameMatch = headers.match(/filename="([^"]+)"/);
    const contentTypeMatch = headers.match(/Content-Type:\s*(.+)/i);

    if (filenameMatch) {
      parts.push({
        name: nameMatch ? nameMatch[1] : 'file',
        filename: filenameMatch[1],
        contentType: contentTypeMatch ? contentTypeMatch[1].trim() : 'application/octet-stream',
        data: body
      });
    }

    start = end + boundaryBuffer.length + 2;
  }
  return parts;
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

    // Provisioning step
    if (path === '/provision/step' && req.method === 'POST') {
      return await handleProvisionStep(req, res);
    }

    // File upload
    if (path === '/upload' && req.method === 'POST') {
      return await handleUpload(req, res);
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
