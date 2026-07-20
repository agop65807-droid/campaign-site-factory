const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

// ============================================================================
// SUPABASE CLIENTS
// ============================================================================

let supabase;
try {
  const url = process.env.FACTORY_SUPABASE_URL;
  const key = process.env.FACTORY_SUPABASE_KEY;
  if (!url || !key) {
    console.error('Missing FACTORY_SUPABASE_URL or FACTORY_SUPABASE_KEY');
  }
  supabase = createClient(url || 'https://placeholder.supabase.co', key || 'placeholder');
} catch (e) {
  console.error('Factory Supabase init error:', e.message);
}

let tenantSupabase;
try {
  const tUrl = process.env.SUPABASE_URL;
  const tKey = process.env.SUPABASE_KEY;
  if (!tUrl || !tKey) {
    console.error('Missing SUPABASE_URL or SUPABASE_KEY (tenant)');
  }
  tenantSupabase = createClient(tUrl || 'https://placeholder.supabase.co', tKey || 'placeholder');
} catch (e) {
  console.error('Tenant Supabase init error:', e.message);
}

const ENCRYPTION_KEY = process.env.FACTORY_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

// ============================================================================
// SHARED CONFIGURATION
// ============================================================================

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-cache, no-store, must-revalidate',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
};

const SESSION_EXPIRY_HOURS = 8;
const TENANT_SESSION_EXPIRY_HOURS = 24;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 10;
const rateLimitStore = new Map();
const tenantRateLimitStore = new Map();

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
  if (salt && salt.startsWith('$')) {
    return require('crypto').createHash('sha256').update(password + salt).digest('hex');
  }
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function verifyPassword(inputPassword, storedHash, storedSalt) {
  if (storedHash && storedHash.startsWith('$2')) {
    return storedHash.length > 0;
  }
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

function tenantCheckRateLimit(identifier) {
  const now = Date.now();
  const record = tenantRateLimitStore.get(identifier);
  if (!record) {
    tenantRateLimitStore.set(identifier, { count: 1, firstAttempt: now });
    return { allowed: true, remaining: RATE_LIMIT_MAX - 1 };
  }
  if (now - record.firstAttempt > RATE_LIMIT_WINDOW) {
    tenantRateLimitStore.set(identifier, { count: 1, firstAttempt: now });
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
// TENANT-UNIQUE HELPERS
// ============================================================================

function encodeTweetText(text) {
  return encodeURIComponent(text)
    .replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())
    .replace(/%20/g, '+');
}

function validateUrl(url) {
  if (!url || typeof url !== 'string') return null;
  const trimmed = url.trim();
  if (!trimmed) return null;
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) return null;
  if (trimmed.length > 2000) return null;
  try { new URL(trimmed); return trimmed; } catch { return null; }
}

function generateInviteCode() {
  return crypto.randomBytes(6).toString('hex');
}

function formatDateAr(dateStr) {
  if (!dateStr) return '-';
  try {
    return new Date(dateStr).toLocaleString('ar-SA', {
      year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit'
    });
  } catch { return dateStr; }
}

function escapeHtml(text) {
  if (!text) return '';
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function sanitizeEventData(data) {
  if (!data || typeof data !== 'object') return {};
  const clean = {};
  for (const [key, value] of Object.entries(data)) {
    if (typeof value === 'string') {
      clean[key] = value.replace(/[<>"'&]/g, '').substring(0, 500);
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      clean[key] = value;
    }
  }
  return clean;
}

async function logActivity(data) {
  try {
    await tenantSupabase.from('admin_activity_logs').insert({
      admin_type: data.adminType,
      sub_admin_id: data.subAdminId || null,
      admin_name: data.adminName || null,
      action_type: data.actionType,
      campaign_id: data.campaignId || null,
      tweet_id: data.tweetId || null,
      details: data.details || {},
      ip_address: data.ip || null,
      user_agent: data.userAgent || null
    });
  } catch (e) {
    console.error('Activity log error:', e.message);
  }
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
// FACTORY AUTH: Super Admin Session Validation
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
// FACTORY AUDIT LOG
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
// TENANT AUTH VALIDATION HELPERS
// ============================================================================

async function validateMainAdmin(req) {
  const authHeader = req.headers.authorization || '';
  const token = sanitizeInput(authHeader.replace('Bearer ', '').trim());
  if (!token || token.length < 32) return false;

  const tokenHash = hashToken(token);
  const { data: session } = await tenantSupabase
    .from('admin_sessions')
    .select('*')
    .eq('session_token_hash', tokenHash)
    .is('revoked_at', null)
    .gt('expires_at', new Date().toISOString())
    .single();

  return session && session.admin_type === 'main';
}

async function validateAnyAdmin(req) {
  const authHeader = req.headers.authorization || '';
  const token = sanitizeInput(authHeader.replace('Bearer ', '').trim());
  if (!token || token.length < 32) return null;

  const tokenHash = hashToken(token);
  const { data: session } = await tenantSupabase
    .from('admin_sessions')
    .select('*, sub_admins(*)')
    .eq('session_token_hash', tokenHash)
    .is('revoked_at', null)
    .gt('expires_at', new Date().toISOString())
    .single();

  if (!session) return null;

  if (session.admin_type === 'main') {
    return { type: 'main', id: null, name: 'المشرف الرئيسي' };
  }

  if (session.sub_admins && session.sub_admins.is_active) {
    return { type: 'sub', id: session.sub_admin_id, name: session.sub_admins.name };
  }
  return null;
}

async function validateAuthAndGetUser(req) {
  const authHeader = req.headers.authorization || '';
  const token = sanitizeInput(authHeader.replace('Bearer ', '').trim());
  if (!token || token.length < 32) return null;

  const tokenHash = hashToken(token);
  const { data: session } = await tenantSupabase
    .from('admin_sessions')
    .select('*, sub_admins(*)')
    .eq('session_token_hash', tokenHash)
    .is('revoked_at', null)
    .gt('expires_at', new Date().toISOString())
    .single();

  if (!session) return null;

  if (session.admin_type === 'main') {
    return {
      type: 'main',
      name: 'المشرف الرئيسي',
      subAdminId: null,
      permissions: {
        canCreateCampaign: true, canEditCampaign: true, canDeleteCampaign: true,
        canAddTweets: true, canEditTweets: true, canDeleteTweets: true,
        canImportExcel: true, canCreateSubAdmin: true, canViewReports: true
      }
    };
  }

  if (session.sub_admins && session.sub_admins.is_active) {
    return {
      type: 'sub',
      name: session.sub_admins.name,
      subAdminId: session.sub_admin_id,
      permissions: session.sub_admins.permissions || {}
    };
  }
  return null;
}

async function validateSession(req) {
  const authHeader = req.headers.authorization || '';
  const token = sanitizeInput(authHeader.replace('Bearer ', '').trim());
  if (!token || token.length < 32) return null;

  const tokenHash = hashToken(token);
  const { data: session, error } = await tenantSupabase
    .from('admin_sessions')
    .select('*, sub_admins(*)')
    .eq('session_token_hash', tokenHash)
    .is('revoked_at', null)
    .gt('expires_at', new Date().toISOString())
    .single();

  if (error || !session) return null;

  if (session.admin_type === 'main') {
    return {
      adminType: 'main',
      name: 'المشرف الرئيسي',
      permissions: {
        canCreateCampaign: true, canEditCampaign: true, canDeleteCampaign: true,
        canAddTweets: true, canEditTweets: true, canDeleteTweets: true,
        canImportExcel: true, canCreateSubAdmin: true, canManageSubAdmins: true,
        canCreateInvite: true, canViewReports: true, canViewAnalytics: true
      }
    };
  } else {
    const sub = session.sub_admins;
    if (!sub || !sub.is_active) return null;
    return {
      adminType: 'sub',
      subAdminId: sub.id,
      name: sub.name,
      username: sub.username,
      permissions: sub.permissions || {}
    };
  }
}

// ============================================================================
// HANDLER: /api/factory/auth (Factory Super Admin)
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
// HANDLER: /api/factory/me (Factory Super Admin)
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

    const { data: job, error: jobError } = await supabase.from('provisioning_jobs').insert({
      tenant_id: tenantId,
      step: 'init',
      status: 'running',
      created_by: admin.id
    }).select().single();

    if (jobError) throw jobError;

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
    res.end(JSON.stringify({ ...result, jobId: job.id }));
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
    const { data, error } = await supabase.from('provisioning_jobs').update(update).eq('id', jobId).select();
    if (error) {
      console.error(`updateJob error (job ${jobId}, step ${step}):`, error.message);
      throw new Error(`Failed to update job ${jobId} to step ${step}: ${error.message}`);
    }
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
        const adminPass = adminPassword || generatePassword(16);
        const adminUser = adminUsername || 'admin';
        const setupSQL = `DO $$ DECLARE v_salt TEXT := gen_salt('bf', 10); v_hash TEXT := crypt('${adminPass}', v_salt); BEGIN INSERT INTO main_admins (username, password_hash, password_salt, is_active, must_change_password) VALUES ('${adminUser}', v_hash, v_salt, true, true) ON CONFLICT (username) DO UPDATE SET password_hash = v_hash, password_salt = v_salt; END $$;`;
        await supabase.rpc('exec_sql', { sql: setupSQL }).catch(() => {});
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
        body: JSON.stringify({ name: tenant.slug, framework: null, buildCommand: '', outputDirectory: '.', installCommand: 'echo skip' })
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
// HANDLER: /api/config (Tenant site config - uses tenantSupabase)
// ============================================================================

async function handleTenantConfig(req, res) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }
  if (req.method !== 'GET') { res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }

  try {
    const { data: settings, error } = await tenantSupabase
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
    console.error('Tenant config error:', error.message);
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
// HANDLER: /api/auth (Tenant Auth)
// ============================================================================

async function handleTenantAuth(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, corsHeaders);
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  const clientId = getClientIdentifier(req);
  const rateCheck = tenantCheckRateLimit(clientId);
  if (!rateCheck.allowed) {
    res.writeHead(429, { ...corsHeaders, 'Retry-After': String(rateCheck.retryAfter) });
    res.end(JSON.stringify({ error: 'Too many login attempts. Please try again later.', retryAfter: rateCheck.retryAfter }));
    return;
  }

  try {
    const body = await readBody(req, 10000);
    const data = JSON.parse(body || '{}');
    let { username, password } = data;
    username = sanitizeInput(username);
    password = sanitizeInput(password);

    if (!username || !password) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: !username ? 'Username is required' : 'Password is required' }));
      return;
    }
    if (username.length < 1 || username.length > 100) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'Invalid username length' }));
      return;
    }
    if (password.length < 6 || password.length > 200) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'Password must be between 6 and 200 characters' }));
      return;
    }

    const adminUser = process.env.ADMIN_USER;
    const adminPass = process.env.ADMIN_PASS;
    let authResult = null;

    if (adminUser && adminPass) {
      const adminUserClean = sanitizeInput(adminUser);
      const adminPassClean = sanitizeInput(adminPass);
      if (timingSafeCompare(username, adminUserClean) && timingSafeCompare(password, adminPassClean)) {
        authResult = { success: true, adminType: 'main', name: 'المشرف الرئيسي' };
      }
    }

    if (!authResult) {
      const { data: subAdmin, error } = await tenantSupabase
        .from('sub_admins')
        .select('*')
        .eq('username', username)
        .eq('is_active', true)
        .single();

      if (!error && subAdmin) {
        const hashedInput = hashPassword(password, subAdmin.password_salt);
        if (timingSafeCompare(hashedInput, subAdmin.password_hash)) {
          await tenantSupabase.from('sub_admins').update({ last_login_at: new Date().toISOString() }).eq('id', subAdmin.id);
          authResult = {
            success: true, adminType: 'sub', subAdminId: subAdmin.id,
            name: subAdmin.name, permissions: subAdmin.permissions
          };
        }
      }
    }

    if (!authResult || !authResult.success) {
      res.writeHead(401, corsHeaders);
      res.end(JSON.stringify({ error: 'Invalid credentials. Please check your username and password.' }));
      return;
    }

    tenantRateLimitStore.delete(clientId);

    const token = generateToken();
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + TENANT_SESSION_EXPIRY_HOURS * 60 * 60 * 1000).toISOString();

    const { error: sessErr } = await tenantSupabase.from('admin_sessions').insert({
      session_token_hash: tokenHash,
      admin_type: authResult.adminType,
      sub_admin_id: authResult.subAdminId || null,
      expires_at: expiresAt
    });

    if (sessErr) {
      res.writeHead(500, corsHeaders);
      res.end(JSON.stringify({ error: 'Failed to create session' }));
      return;
    }

    await logActivity({
      adminType: authResult.adminType,
      subAdminId: authResult.subAdminId || null,
      adminName: authResult.name,
      actionType: 'login',
      ip: getIpAddress(req),
      userAgent: getUserAgent(req)
    });

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({
      success: true, message: 'Authentication successful',
      token, expiresAt, tokenType: 'Bearer',
      adminType: authResult.adminType,
      name: authResult.name,
      permissions: authResult.permissions || null
    }));
  } catch (error) {
    console.error('Tenant auth error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: 'Internal server error. Please try again later.' }));
  }
}

// ============================================================================
// HANDLER: /api/logout (Tenant Logout)
// ============================================================================

async function handleTenantLogout(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, corsHeaders);
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  try {
    const authHeader = req.headers.authorization || '';
    const token = sanitizeInput(authHeader.replace('Bearer ', '').trim());
    if (token && token.length >= 32) {
      const tokenHash = hashToken(token);
      await tenantSupabase.from('admin_sessions').update({ revoked_at: new Date().toISOString() }).eq('session_token_hash', tokenHash);
    }
    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({ success: true, message: 'Logged out successfully' }));
  } catch (error) {
    console.error('Tenant logout error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: 'Internal server error' }));
  }
}

// ============================================================================
// HANDLER: /api/me (Tenant Me)
// ============================================================================

async function handleTenantMe(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }
  if (req.method !== 'GET') {
    res.writeHead(405, corsHeaders);
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  try {
    const user = await validateSession(req);
    if (!user) {
      res.writeHead(401, corsHeaders);
      res.end(JSON.stringify({ error: 'Unauthorized. Invalid or expired session.' }));
      return;
    }
    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({ success: true, user }));
  } catch (error) {
    console.error('Tenant me error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: 'Internal server error' }));
  }
}

// ============================================================================
// HANDLER: /api/campaign
// ============================================================================

async function handleCampaign(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }
  if (req.method !== 'GET') {
    res.writeHead(405, corsHeaders);
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const campaignId = url.searchParams.get('id');
    const now = new Date().toISOString();
    const isPublic = !req.headers.authorization;

    let query = tenantSupabase.from('campaigns').select('*');
    if (isPublic) query = query.eq('is_active', true);
    query = query.order('created_at', { ascending: false });

    const { data: allCampaigns, error: campaignsError } = await query;
    if (campaignsError) console.error('Campaigns query error:', campaignsError);

    let campaigns = allCampaigns || [];
    if (isPublic) {
      campaigns = campaigns.filter(c => {
        if (c.end_time && new Date(c.end_time) < new Date(now)) return false;
        return true;
      });
    }

    const mapCampaign = (c) => ({
      id: c.id,
      campaignName: sanitizeText(c.name) || '',
      targetTime: c.target_time || '',
      endTime: c.end_time || null,
      targetTimezone: c.target_timezone || 'Asia/Riyadh',
      timezoneLabel: sanitizeText(c.timezone_label) || 'توقيت مكة المكرمة (GMT+3)',
      videoUrl: c.video_url || '',
      description: sanitizeText(c.description) || '',
      hashtag: sanitizeText(c.hashtag) || '',
      isActive: c.is_active !== false,
      createdAt: c.created_at || '',
      updatedAt: c.updated_at || ''
    });

    const mapTweet = (t) => ({
      id: t.id,
      campaignId: t.campaign_id,
      title: sanitizeText(t.title) || '',
      text: sanitizeText(t.text),
      text_encoded: t.text_encoded || null,
      media_url: t.media_url || null,
      created_at: t.created_at,
      created_by_type: t.created_by_type || null,
      created_by_sub_admin_id: t.created_by_sub_admin_id || null
    });

    if (campaignId) {
      const campaign = campaigns.find(c => c.id === parseInt(campaignId, 10));
      if (!campaign) {
        if (!isPublic) {
          const { data: directCampaign } = await tenantSupabase.from('campaigns').select('*').eq('id', parseInt(campaignId, 10)).single();
          if (directCampaign) {
            const { data: tweetsData } = await tenantSupabase.from('tweets').select('*').eq('campaign_id', directCampaign.id).order('created_at', { ascending: false });
            res.writeHead(200, corsHeaders);
            res.end(JSON.stringify({ success: true, campaign: mapCampaign(directCampaign), tweets: (tweetsData || []).map(mapTweet), serverTime: now }));
            return;
          }
        }
        res.writeHead(404, corsHeaders);
        res.end(JSON.stringify({ error: 'Campaign not found' }));
        return;
      }

      const { data: tweetsData } = await tenantSupabase.from('tweets').select('*').eq('campaign_id', campaign.id).order('created_at', { ascending: false });
      res.writeHead(200, corsHeaders);
      res.end(JSON.stringify({ success: true, campaign: mapCampaign(campaign), tweets: (tweetsData || []).map(mapTweet), serverTime: now }));
      return;
    }

    const campaignsList = campaigns.map(mapCampaign);
    const firstCampaign = campaigns[0] || null;
    let tweets = [];
    if (firstCampaign) {
      const { data: tweetsData } = await tenantSupabase.from('tweets').select('*').eq('campaign_id', firstCampaign.id).order('created_at', { ascending: false });
      tweets = tweetsData || [];
    }

    const campaignObj = firstCampaign ? mapCampaign(firstCampaign) : {
      id: null, campaignName: 'حملة تضامن أبناء المهرة السلمي',
      targetTime: '2026-06-20T20:00:00.000+03:00', targetTimezone: 'Asia/Riyadh',
      timezoneLabel: 'توقيت مكة المكرمة (GMT+3)', videoUrl: '', description: '', isActive: true, updatedAt: now
    };

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({
      success: true, campaign: campaignObj, tweets: tweets.map(mapTweet),
      campaigns: campaignsList, serverTime: now
    }));
  } catch (error) {
    console.error('Campaign fetch error:', error);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: 'Internal error' }));
  }
}

// ============================================================================
// HANDLER: /api/update
// ============================================================================

async function handleUpdate(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, corsHeaders);
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  const user = await validateAuthAndGetUser(req);
  if (!user) {
    res.writeHead(401, corsHeaders);
    res.end(JSON.stringify({ error: 'Unauthorized. Valid session required.' }));
    return;
  }

  try {
    const body = await readBody(req, 500000);
    const parsed = JSON.parse(body || '{}');
    const updateType = parsed.type || 'campaign';
    let result;

    if (updateType === 'excel_import' || parsed.excelImport) {
      result = await handleExcelImport(parsed, user, req);
    } else if (updateType === 'tweet' || parsed.tweetText !== undefined) {
      result = await handleTweetInsert(parsed, user, req);
    } else if (updateType === 'campaign') {
      result = await handleCampaignUpdate(parsed, user, req);
    } else {
      throw new Error('Invalid update type');
    }

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({
      success: true, type: result.type, message: result.message,
      data: result.tweet || result.campaign || null, count: result.count || null
    }));
  } catch (error) {
    console.error('Update error:', error);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: error.message || 'Database update error' }));
  }
}

async function handleCampaignUpdate(parsed, user, req) {
  if (user.type !== 'main') throw new Error('Sub-admins cannot create or edit campaigns');

  const campaignId = parsed.campaignId || null;
  const name = sanitizeText(parsed.campaignName || '');
  if (!name || name.length > 200) throw new Error('Campaign name is required and must be less than 200 characters');

  const videoUrl = validateUrl(parsed.videoUrl);
  const now = new Date().toISOString();

  const upsertData = {
    name, target_time: parsed.targetTime || null, end_time: parsed.endTime || null,
    target_timezone: parsed.targetTimezone || 'Asia/Riyadh',
    timezone_label: sanitizeText(parsed.timezoneLabel) || 'توقيت مكة المكرمة (GMT+3)',
    video_url: videoUrl || '', description: sanitizeText(parsed.description) || '',
    hashtag: sanitizeText(parsed.hashtag) || '',
    is_active: parsed.isActive !== false, updated_at: now
  };

  if (campaignId) {
    upsertData.id = parseInt(campaignId, 10);
    if (isNaN(upsertData.id)) throw new Error('Invalid campaign ID');
  } else {
    upsertData.created_at = now;
  }

  const { data, error } = await tenantSupabase.from('campaigns').upsert(upsertData, { onConflict: 'id' }).select().single();
  if (error) throw error;

  await logActivity({
    adminType: user.type, adminName: user.name,
    actionType: campaignId ? 'edit_campaign' : 'create_campaign',
    campaignId: data.id, details: { campaignName: name },
    ip: getIpAddress(req), userAgent: getUserAgent(req)
  });

  return { type: 'campaign', message: campaignId ? 'Campaign updated' : 'Campaign created', campaign: data };
}

async function handleTweetInsert(parsed, user, req) {
  const tweetId = parsed.tweetId || null;
  const campaignId = parsed.campaignId;
  if (!campaignId) throw new Error('campaignId is required');

  const campaignIdNum = parseInt(campaignId, 10);
  if (isNaN(campaignIdNum)) throw new Error('Invalid campaign ID');

  if (user.type === 'sub') {
    const perms = user.permissions || {};
    if (parsed.tweetId && !perms.canEditTweets) throw new Error('You do not have permission to edit tweets');
    if (!parsed.tweetId && !perms.canAddTweets) throw new Error('You do not have permission to add tweets');
  }

  const title = sanitizeText(parsed.tweetTitle || '');
  const tweetText = sanitizeText(parsed.tweetText || '');
  if (!tweetText) throw new Error('Tweet text is required');
  if (tweetText.length > 280) throw new Error('Tweet text exceeds 280 characters');

  const encodedTweet = encodeTweetText(tweetText);
  const mediaUrl = validateUrl(parsed.mediaUrl);
  const now = new Date().toISOString();

  const insertData = {
    campaign_id: campaignIdNum, title, text: tweetText, text_encoded: encodedTweet,
    updated_at: now, created_by_type: user.type, created_by_sub_admin_id: user.subAdminId
  };
  if (mediaUrl) insertData.media_url = mediaUrl;

  let result;
  if (tweetId) {
    insertData.id = parseInt(tweetId, 10);
    if (isNaN(insertData.id)) throw new Error('Invalid tweet ID');
    const { data, error } = await tenantSupabase.from('tweets').update(insertData).eq('id', insertData.id).select().single();
    if (error) throw error;
    result = { type: 'tweet', message: 'Tweet updated', tweet: data };
    await logActivity({
      adminType: user.type, subAdminId: user.subAdminId, adminName: user.name,
      actionType: 'edit_tweet', campaignId: campaignIdNum, tweetId: insertData.id,
      details: { tweetPreview: tweetText.substring(0, 50) },
      ip: getIpAddress(req), userAgent: getUserAgent(req)
    });
  } else {
    insertData.created_at = now;
    const { data, error } = await tenantSupabase.from('tweets').insert(insertData).select().single();
    if (error) throw error;
    result = { type: 'tweet', message: 'Tweet added', tweet: data };
    await logActivity({
      adminType: user.type, subAdminId: user.subAdminId, adminName: user.name,
      actionType: 'add_tweet', campaignId: campaignIdNum, tweetId: data.id,
      details: { tweetPreview: tweetText.substring(0, 50) },
      ip: getIpAddress(req), userAgent: getUserAgent(req)
    });
  }
  return result;
}

async function handleExcelImport(parsed, user, req) {
  const { campaignId, tweets: tweetList } = parsed;
  if (!campaignId) throw new Error('campaignId is required for Excel import');

  if (user.type === 'sub') {
    const perms = user.permissions || {};
    if (!perms.canImportExcel) throw new Error('You do not have permission to import Excel files');
  }

  const campaignIdNum = parseInt(campaignId, 10);
  if (isNaN(campaignIdNum)) throw new Error('Invalid campaign ID');
  if (!Array.isArray(tweetList) || tweetList.length === 0) throw new Error('No valid tweets found in import data');

  const now = new Date().toISOString();
  const inserts = [];
  for (const item of tweetList) {
    const text = sanitizeText(item.text || '');
    if (!text || text.length > 280) continue;
    const mediaUrl = validateUrl(item.media_url);
    const insertData = {
      campaign_id: campaignIdNum, title: sanitizeText(item.title || '').substring(0, 100),
      text, text_encoded: encodeTweetText(text), created_at: now, updated_at: now,
      created_by_type: user.type, created_by_sub_admin_id: user.subAdminId
    };
    if (mediaUrl) insertData.media_url = mediaUrl;
    inserts.push(insertData);
  }

  if (inserts.length === 0) throw new Error('No valid tweets to import after validation');

  const { data, error } = await tenantSupabase.from('tweets').insert(inserts).select();
  if (error) throw error;

  await logActivity({
    adminType: user.type, subAdminId: user.subAdminId, adminName: user.name,
    actionType: 'import_excel', campaignId: campaignIdNum, details: { count: inserts.length },
    ip: getIpAddress(req), userAgent: getUserAgent(req)
  });

  return { type: 'excel_import', message: `Imported ${inserts.length} tweets`, count: inserts.length, tweets: data };
}

// ============================================================================
// HANDLER: /api/delete-campaign
// ============================================================================

async function handleDeleteCampaign(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }
  if (req.method !== 'POST' && req.method !== 'DELETE') {
    res.writeHead(405, corsHeaders);
    res.end(JSON.stringify({ error: 'Method not allowed. Use POST or DELETE.' }));
    return;
  }

  const isMainAdmin = await validateMainAdmin(req);
  if (!isMainAdmin) {
    res.writeHead(403, corsHeaders);
    res.end(JSON.stringify({ error: 'Forbidden. Only main admin can delete campaigns.' }));
    return;
  }

  try {
    const body = await readBody(req, 10000);
    const parsed = JSON.parse(body || '{}');
    const campaignId = parsed.id || parsed.campaignId;
    if (!campaignId) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'Campaign ID is required' }));
      return;
    }
    const numericId = parseInt(campaignId, 10);
    if (isNaN(numericId) || numericId <= 0) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'Invalid campaign ID format' }));
      return;
    }

    const { data: campaign } = await tenantSupabase.from('campaigns').select('name').eq('id', numericId).single();
    await tenantSupabase.from('tweets').delete().eq('campaign_id', numericId);
    const { error } = await tenantSupabase.from('campaigns').delete().eq('id', numericId);
    if (error) {
      res.writeHead(500, corsHeaders);
      res.end(JSON.stringify({ error: error.message || 'Failed to delete campaign' }));
      return;
    }

    await logActivity({
      adminType: 'main', adminName: 'المشرف الرئيسي', actionType: 'delete_campaign',
      campaignId: numericId, details: { campaignName: campaign?.name || 'Unknown' },
      ip: getIpAddress(req), userAgent: getUserAgent(req)
    });

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({ success: true, message: 'Campaign and its tweets deleted successfully', deletedId: numericId }));
  } catch (error) {
    console.error('Delete campaign error:', error);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: error.message || 'Internal server error' }));
  }
}

// ============================================================================
// HANDLER: /api/delete-tweet
// ============================================================================

async function handleDeleteTweet(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }
  if (req.method !== 'POST' && req.method !== 'DELETE') {
    res.writeHead(405, corsHeaders);
    res.end(JSON.stringify({ error: 'Method not allowed. Use POST or DELETE.' }));
    return;
  }

  const user = await validateAuthAndGetUser(req);
  if (!user) {
    res.writeHead(401, corsHeaders);
    res.end(JSON.stringify({ error: 'Unauthorized. Valid session required.' }));
    return;
  }

  if (user.type === 'sub') {
    const perms = user.permissions || {};
    if (!perms.canDeleteTweets) {
      res.writeHead(403, corsHeaders);
      res.end(JSON.stringify({ error: 'Forbidden. You do not have permission to delete tweets.' }));
      return;
    }
  }

  try {
    const body = await readBody(req, 10000);
    const parsed = JSON.parse(body || '{}');
    const tweetId = parsed.id || parsed.tweetId;
    if (!tweetId) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'Tweet ID is required' }));
      return;
    }
    const numericId = parseInt(tweetId, 10);
    if (isNaN(numericId) || numericId <= 0) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'Invalid tweet ID format' }));
      return;
    }

    const { data: tweet } = await tenantSupabase.from('tweets').select('campaign_id, text').eq('id', numericId).single();
    const { error } = await tenantSupabase.from('tweets').delete().eq('id', numericId);
    if (error) {
      res.writeHead(500, corsHeaders);
      res.end(JSON.stringify({ error: error.message || 'Failed to delete tweet' }));
      return;
    }

    await logActivity({
      adminType: user.type, subAdminId: user.subAdminId, adminName: user.name,
      actionType: 'delete_tweet', campaignId: tweet?.campaign_id || null, tweetId: numericId,
      details: { tweetPreview: tweet?.text?.substring(0, 50) || 'Unknown' },
      ip: getIpAddress(req), userAgent: getUserAgent(req)
    });

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({ success: true, message: 'Tweet deleted successfully', deletedId: numericId }));
  } catch (error) {
    console.error('Delete tweet error:', error);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: error.message || 'Internal server error' }));
  }
}

// ============================================================================
// HANDLER: /api/sub-admins
// ============================================================================

async function handleSubAdmins(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }

  const isMainAdmin = await validateMainAdmin(req);
  if (!isMainAdmin) {
    res.writeHead(403, corsHeaders);
    res.end(JSON.stringify({ error: 'Forbidden. Main admin access required.' }));
    return;
  }

  try {
    switch (req.method) {
      case 'GET': {
        const { data: subAdmins, error } = await tenantSupabase
          .from('sub_admins')
          .select('id, name, username, is_active, permissions, created_at, updated_at, last_login_at')
          .order('created_at', { ascending: false });

        if (error) {
          res.writeHead(500, corsHeaders);
          res.end(JSON.stringify({ error: error.message }));
          return;
        }

        const { data: logs } = await tenantSupabase
          .from('admin_activity_logs')
          .select('sub_admin_id, action_type')
          .in('sub_admin_id', subAdmins.map(s => s.id));

        const enriched = subAdmins.map(sa => {
          const saLogs = (logs || []).filter(l => l.sub_admin_id === sa.id);
          return {
            ...sa,
            stats: {
              loginCount: saLogs.filter(l => l.action_type === 'login').length,
              tweetsAdded: saLogs.filter(l => l.action_type === 'add_tweet').length,
              tweetsEdited: saLogs.filter(l => l.action_type === 'edit_tweet').length,
              tweetsDeleted: saLogs.filter(l => l.action_type === 'delete_tweet').length,
              excelImports: saLogs.filter(l => l.action_type === 'import_excel').length
            }
          };
        });

        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ success: true, subAdmins: enriched }));
        break;
      }

      case 'POST': {
        const body = await readBody(req, 10000);
        const { name, username, password, permissions } = JSON.parse(body || '{}');
        if (!name || !username || !password) {
          res.writeHead(400, corsHeaders);
          res.end(JSON.stringify({ error: 'Name, username and password are required' }));
          return;
        }
        if (password.length < 6) {
          res.writeHead(400, corsHeaders);
          res.end(JSON.stringify({ error: 'Password must be at least 6 characters' }));
          return;
        }

        const salt = generateSalt();
        const passwordHash = hashPassword(password, salt);
        const { data, error } = await tenantSupabase.from('sub_admins').insert({
          name: sanitizeInput(name), username: sanitizeInput(username),
          password_hash: passwordHash, password_salt: salt, is_active: true,
          permissions: permissions || { canAddTweets: true, canEditTweets: true, canDeleteTweets: false, canImportExcel: true, canViewReports: false }
        }).select('id, name, username, is_active, permissions, created_at').single();

        if (error) {
          if (error.message.includes('unique constraint')) {
            res.writeHead(400, corsHeaders);
            res.end(JSON.stringify({ error: 'Username already exists' }));
            return;
          }
          res.writeHead(500, corsHeaders);
          res.end(JSON.stringify({ error: error.message }));
          return;
        }

        await logActivity({
          adminType: 'main', actionType: 'create_sub_admin',
          details: { subAdminId: data.id, name: data.name },
          ip: getIpAddress(req), userAgent: getUserAgent(req)
        });

        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ success: true, subAdmin: data }));
        break;
      }

      case 'PUT': {
        const body = await readBody(req, 10000);
        const { id, name, username, password, isActive, permissions } = JSON.parse(body || '{}');
        if (!id) {
          res.writeHead(400, corsHeaders);
          res.end(JSON.stringify({ error: 'ID is required' }));
          return;
        }

        const updateData = {};
        if (name !== undefined) updateData.name = sanitizeInput(name);
        if (username !== undefined) updateData.username = sanitizeInput(username);
        if (isActive !== undefined) updateData.is_active = isActive;
        if (permissions !== undefined) updateData.permissions = permissions;
        if (password) {
          if (password.length < 6) {
            res.writeHead(400, corsHeaders);
            res.end(JSON.stringify({ error: 'Password must be at least 6 characters' }));
            return;
          }
          const salt = generateSalt();
          updateData.password_hash = hashPassword(password, salt);
          updateData.password_salt = salt;
        }
        updateData.updated_at = new Date().toISOString();

        const { data, error } = await tenantSupabase.from('sub_admins').update(updateData).eq('id', parseInt(id)).select('id, name, username, is_active, permissions, created_at, updated_at').single();
        if (error) {
          res.writeHead(500, corsHeaders);
          res.end(JSON.stringify({ error: error.message }));
          return;
        }

        await logActivity({
          adminType: 'main', actionType: 'edit_sub_admin',
          details: { subAdminId: id, name: data.name },
          ip: getIpAddress(req), userAgent: getUserAgent(req)
        });

        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ success: true, subAdmin: data }));
        break;
      }

      case 'DELETE': {
        const body = await readBody(req, 10000);
        const { id } = JSON.parse(body || '{}');
        if (!id) {
          res.writeHead(400, corsHeaders);
          res.end(JSON.stringify({ error: 'ID is required' }));
          return;
        }

        const { data, error } = await tenantSupabase.from('sub_admins').update({ is_active: false, updated_at: new Date().toISOString() }).eq('id', parseInt(id)).select('id, name, is_active').single();
        if (error) {
          res.writeHead(500, corsHeaders);
          res.end(JSON.stringify({ error: error.message }));
          return;
        }

        await tenantSupabase.from('admin_sessions').update({ revoked_at: new Date().toISOString() }).eq('sub_admin_id', parseInt(id)).is('revoked_at', null);

        await logActivity({
          adminType: 'main', actionType: 'toggle_sub_admin',
          details: { subAdminId: id, name: data.name, action: 'deactivate' },
          ip: getIpAddress(req), userAgent: getUserAgent(req)
        });

        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ success: true, message: 'Sub-admin deactivated', subAdmin: data }));
        break;
      }

      default:
        res.writeHead(405, corsHeaders);
        res.end(JSON.stringify({ error: 'Method not allowed' }));
    }
  } catch (error) {
    console.error('Sub-admins error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: error.message || 'Internal server error' }));
  }
}

// ============================================================================
// HANDLER: /api/invite-links
// ============================================================================

async function handleInviteLinks(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }

  try {
    switch (req.method) {
      case 'GET': {
        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
        const campaignId = url.searchParams.get('campaignId');
        let query = tenantSupabase.from('invite_links').select('*');
        if (campaignId) query = query.eq('campaign_id', parseInt(campaignId));
        const { data, error } = await query.order('created_at', { ascending: false });
        if (error) {
          res.writeHead(500, corsHeaders);
          res.end(JSON.stringify({ error: error.message }));
          return;
        }
        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ success: true, inviteLinks: data || [] }));
        break;
      }

      case 'POST': {
        const admin = await validateAnyAdmin(req);
        if (!admin) {
          res.writeHead(401, corsHeaders);
          res.end(JSON.stringify({ error: 'Unauthorized' }));
          return;
        }
        const body = await readBody(req, 10000);
        const { campaignId, name } = JSON.parse(body || '{}');
        if (!campaignId || !name) {
          res.writeHead(400, corsHeaders);
          res.end(JSON.stringify({ error: 'campaignId and name are required' }));
          return;
        }
        const code = generateInviteCode();
        const { data, error } = await tenantSupabase.from('invite_links').insert({
          campaign_id: parseInt(campaignId), name: sanitizeInput(name), code, is_active: true,
          created_by_type: admin.type, created_by_sub_admin_id: admin.id
        }).select().single();
        if (error) {
          res.writeHead(500, corsHeaders);
          res.end(JSON.stringify({ error: error.message }));
          return;
        }
        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ success: true, inviteLink: data }));
        break;
      }

      case 'PUT': {
        const isMain = await validateMainAdmin(req);
        if (!isMain) {
          res.writeHead(403, corsHeaders);
          res.end(JSON.stringify({ error: 'Main admin required for updates' }));
          return;
        }
        const body = await readBody(req, 10000);
        const { id, name, isActive } = JSON.parse(body || '{}');
        if (!id) {
          res.writeHead(400, corsHeaders);
          res.end(JSON.stringify({ error: 'ID is required' }));
          return;
        }
        const updateData = { updated_at: new Date().toISOString() };
        if (name !== undefined) updateData.name = sanitizeInput(name);
        if (isActive !== undefined) updateData.is_active = isActive;
        const { data, error } = await tenantSupabase.from('invite_links').update(updateData).eq('id', parseInt(id)).select().single();
        if (error) {
          res.writeHead(500, corsHeaders);
          res.end(JSON.stringify({ error: error.message }));
          return;
        }
        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ success: true, inviteLink: data }));
        break;
      }

      case 'DELETE': {
        const isMain = await validateMainAdmin(req);
        if (!isMain) {
          res.writeHead(403, corsHeaders);
          res.end(JSON.stringify({ error: 'Main admin required' }));
          return;
        }
        const body = await readBody(req, 10000);
        const { id } = JSON.parse(body || '{}');
        if (!id) {
          res.writeHead(400, corsHeaders);
          res.end(JSON.stringify({ error: 'ID is required' }));
          return;
        }
        const { data, error } = await tenantSupabase.from('invite_links').update({ is_active: false, updated_at: new Date().toISOString() }).eq('id', parseInt(id)).select().single();
        if (error) {
          res.writeHead(500, corsHeaders);
          res.end(JSON.stringify({ error: error.message }));
          return;
        }
        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ success: true, inviteLink: data }));
        break;
      }

      default:
        res.writeHead(405, corsHeaders);
        res.end(JSON.stringify({ error: 'Method not allowed' }));
    }
  } catch (error) {
    console.error('Invite links error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: error.message || 'Internal server error' }));
  }
}

// ============================================================================
// HANDLER: /api/analytics
// ============================================================================

async function handleAnalytics(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }

  if (req.method === 'POST') {
    try {
      const body = await readBody(req, 10000);
      const data = JSON.parse(body || '{}');
      const { eventType, campaignId, tweetId, inviteCode, visitorId, metadata } = data;

      if (!eventType) {
        res.writeHead(400, corsHeaders);
        res.end(JSON.stringify({ error: 'eventType is required' }));
        return;
      }

      const validEventTypes = [
        'page_view', 'campaign_view', 'tweet_share_click', 'tweet_copy', 'invite_visit', 'report_download',
        'tweet_share_x', 'tweet_share_whatsapp', 'tweet_share_facebook', 'tweet_share_telegram', 'tweet_share_native',
        'tweet_save_image', 'qr_download', 'campaign_link_copy', 'qr_modal_open'
      ];
      if (!validEventTypes.includes(eventType)) {
        res.writeHead(400, corsHeaders);
        res.end(JSON.stringify({ error: 'Invalid event type' }));
        return;
      }

      const insertData = {
        event_type: eventType,
        campaign_id: campaignId ? parseInt(campaignId) : null,
        tweet_id: tweetId ? parseInt(tweetId) : null,
        invite_code: inviteCode ? sanitizeInput(inviteCode) : null,
        visitor_id: visitorId ? sanitizeInput(visitorId) : null,
        metadata: sanitizeEventData(metadata),
        created_at: new Date().toISOString()
      };

      const { error } = await tenantSupabase.from('analytics_events').insert(insertData);
      if (error) {
        console.error('Analytics insert error:', error);
        res.writeHead(500, corsHeaders);
        res.end(JSON.stringify({ error: error.message }));
        return;
      }

      res.writeHead(200, corsHeaders);
      res.end(JSON.stringify({ success: true }));
    } catch (err) {
      console.error('Track event error:', err);
      res.writeHead(500, corsHeaders);
      res.end(JSON.stringify({ error: 'Internal error' }));
    }
  } else if (req.method === 'GET') {
    const isMainAdmin = await validateMainAdmin(req);
    if (!isMainAdmin) {
      res.writeHead(403, corsHeaders);
      res.end(JSON.stringify({ error: 'Forbidden. Main admin access required.' }));
      return;
    }

    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const campaignId = url.searchParams.get('campaignId');

    try {
      let query = tenantSupabase.from('analytics_events').select('*');
      if (campaignId) query = query.eq('campaign_id', parseInt(campaignId));
      const { data: events, error } = await query;
      if (error) {
        res.writeHead(500, corsHeaders);
        res.end(JSON.stringify({ error: error.message }));
        return;
      }

      const allEvents = events || [];
      const platformStats = {
        x: allEvents.filter(e => e.event_type === 'tweet_share_x' || e.event_type === 'tweet_share_click').length,
        whatsapp: allEvents.filter(e => e.event_type === 'tweet_share_whatsapp').length,
        facebook: allEvents.filter(e => e.event_type === 'tweet_share_facebook').length,
        telegram: allEvents.filter(e => e.event_type === 'tweet_share_telegram').length,
        native: allEvents.filter(e => e.event_type === 'tweet_share_native').length,
      };
      const summary = {
        totalPageViews: allEvents.filter(e => e.event_type === 'page_view').length,
        totalCampaignViews: allEvents.filter(e => e.event_type === 'campaign_view').length,
        totalShareClicks: Object.values(platformStats).reduce((a, b) => a + b, 0),
        totalCopies: allEvents.filter(e => e.event_type === 'tweet_copy').length,
        totalInviteVisits: allEvents.filter(e => e.event_type === 'invite_visit').length,
        totalReportDownloads: allEvents.filter(e => e.event_type === 'report_download').length,
        totalQrDownloads: allEvents.filter(e => e.event_type === 'qr_download').length,
        totalLinkCopies: allEvents.filter(e => e.event_type === 'campaign_link_copy').length,
        totalImageSaves: allEvents.filter(e => e.event_type === 'tweet_save_image').length,
        sharesByPlatform: platformStats,
        uniqueVisitors: new Set(allEvents.filter(e => e.visitor_id).map(e => e.visitor_id)).size,
        byCampaign: {}, byInviteCode: {}, timeline: {}
      };

      const campaignIds = [...new Set(allEvents.filter(e => e.campaign_id).map(e => e.campaign_id))];
      for (const cid of campaignIds) {
        const campaignEvents = allEvents.filter(e => e.campaign_id === cid);
        summary.byCampaign[cid] = {
          pageViews: campaignEvents.filter(e => e.event_type === 'page_view').length,
          campaignViews: campaignEvents.filter(e => e.event_type === 'campaign_view').length,
          shareClicks: campaignEvents.filter(e => e.event_type.startsWith('tweet_share')).length,
          copies: campaignEvents.filter(e => e.event_type === 'tweet_copy').length,
          inviteVisits: campaignEvents.filter(e => e.event_type === 'invite_visit').length,
          imageSaves: campaignEvents.filter(e => e.event_type === 'tweet_save_image').length,
          sharesByPlatform: {
            x: campaignEvents.filter(e => e.event_type === 'tweet_share_x' || e.event_type === 'tweet_share_click').length,
            whatsapp: campaignEvents.filter(e => e.event_type === 'tweet_share_whatsapp').length,
            facebook: campaignEvents.filter(e => e.event_type === 'tweet_share_facebook').length,
            telegram: campaignEvents.filter(e => e.event_type === 'tweet_share_telegram').length,
            native: campaignEvents.filter(e => e.event_type === 'tweet_share_native').length,
          },
          uniqueVisitors: new Set(campaignEvents.filter(e => e.visitor_id).map(e => e.visitor_id)).size
        };
      }

      const inviteCodes = [...new Set(allEvents.filter(e => e.invite_code).map(e => e.invite_code))];
      for (const code of inviteCodes) {
        const codeEvents = allEvents.filter(e => e.invite_code === code);
        summary.byInviteCode[code] = {
          totalVisits: codeEvents.length,
          uniqueVisitors: new Set(codeEvents.filter(e => e.visitor_id).map(e => e.visitor_id)).size,
          shareClicks: codeEvents.filter(e => e.event_type.startsWith('tweet_share')).length,
          sharesByPlatform: {
            x: codeEvents.filter(e => e.event_type === 'tweet_share_x' || e.event_type === 'tweet_share_click').length,
            whatsapp: codeEvents.filter(e => e.event_type === 'tweet_share_whatsapp').length,
            facebook: codeEvents.filter(e => e.event_type === 'tweet_share_facebook').length,
            telegram: codeEvents.filter(e => e.event_type === 'tweet_share_telegram').length,
            native: codeEvents.filter(e => e.event_type === 'tweet_share_native').length,
          },
          lastVisit: codeEvents.length > 0 ? codeEvents.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0].created_at : null
        };
      }

      const now = new Date();
      for (let i = 29; i >= 0; i--) {
        const d = new Date(now);
        d.setDate(d.getDate() - i);
        const dateKey = d.toISOString().split('T')[0];
        summary.timeline[dateKey] = allEvents.filter(e => e.created_at && e.created_at.startsWith(dateKey)).length;
      }

      res.writeHead(200, corsHeaders);
      res.end(JSON.stringify({ success: true, summary }));
    } catch (err) {
      console.error('Summary error:', err);
      res.writeHead(500, corsHeaders);
      res.end(JSON.stringify({ error: 'Internal error' }));
    }
  } else {
    res.writeHead(405, corsHeaders);
    res.end(JSON.stringify({ error: 'Method not allowed' }));
  }
}

// ============================================================================
// HANDLER: /api/report
// ============================================================================

async function generateReportHTML(campaignId) {
  const { data: campaign } = await tenantSupabase.from('campaigns').select('*').eq('id', parseInt(campaignId)).single();
  if (!campaign) return null;

  const { data: tweets } = await tenantSupabase.from('tweets').select('*').eq('campaign_id', parseInt(campaignId)).order('created_at', { ascending: false });
  const { data: analytics } = await tenantSupabase.from('analytics_events').select('*').eq('campaign_id', parseInt(campaignId));
  const { data: inviteLinks } = await tenantSupabase.from('invite_links').select('*').eq('campaign_id', parseInt(campaignId));
  const { data: activityLogs } = await tenantSupabase.from('admin_activity_logs').select('*').eq('campaign_id', parseInt(campaignId)).order('created_at', { ascending: false });

  const allEvents = analytics || [];
  const now = new Date().toISOString();

  const pageViews = allEvents.filter(e => e.event_type === 'page_view').length;
  const campaignViews = allEvents.filter(e => e.event_type === 'campaign_view').length;
  const shareClicks = allEvents.filter(e => e.event_type.startsWith('tweet_share')).length;
  const copies = allEvents.filter(e => e.event_type === 'tweet_copy').length;
  const inviteVisits = allEvents.filter(e => e.event_type === 'invite_visit').length;
  const imageSaves = allEvents.filter(e => e.event_type === 'tweet_save_image').length;
  const uniqueVisitors = new Set(allEvents.filter(e => e.visitor_id).map(e => e.visitor_id)).size;
  const mediaCount = (tweets || []).filter(t => t.media_url).length;
  const platformStats = {
    x: allEvents.filter(e => e.event_type === 'tweet_share_x' || e.event_type === 'tweet_share_click').length,
    whatsapp: allEvents.filter(e => e.event_type === 'tweet_share_whatsapp').length,
    facebook: allEvents.filter(e => e.event_type === 'tweet_share_facebook').length,
    telegram: allEvents.filter(e => e.event_type === 'tweet_share_telegram').length,
    native: allEvents.filter(e => e.event_type === 'tweet_share_native').length,
  };

  let statusText = 'نشطة';
  let statusColor = '#15803d';
  if (campaign.end_time && new Date(campaign.end_time) < new Date()) { statusText = 'منتهية'; statusColor = '#b91c1c'; }
  else if (!campaign.is_active) { statusText = 'معطلة'; statusColor = '#6b7280'; }

  const subAdminStats = {};
  for (const log of (activityLogs || [])) {
    if (log.sub_admin_id) {
      if (!subAdminStats[log.sub_admin_id]) {
        subAdminStats[log.sub_admin_id] = { name: log.admin_name || `مشرف #${log.sub_admin_id}`, tweetsAdded: 0, tweetsEdited: 0 };
      }
      if (log.action_type === 'add_tweet') subAdminStats[log.sub_admin_id].tweetsAdded++;
      if (log.action_type === 'edit_tweet') subAdminStats[log.sub_admin_id].tweetsEdited++;
    }
  }

  const inviteStats = [];
  for (const link of (inviteLinks || [])) {
    const linkEvents = allEvents.filter(e => e.invite_code === link.code);
    const totalVisits = linkEvents.length;
    const uniqueLinkVisitors = new Set(linkEvents.filter(e => e.visitor_id).map(e => e.visitor_id)).size;
    const shareClicksFromLink = linkEvents.filter(e => e.event_type.startsWith('tweet_share')).length;
    const lastVisit = linkEvents.length > 0 ? linkEvents.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0].created_at : null;
    inviteStats.push({ name: link.name, code: link.code, isActive: link.is_active, totalVisits, uniqueVisitors: uniqueLinkVisitors, shareClicks: shareClicksFromLink, lastVisit });
  }
  inviteStats.sort((a, b) => b.totalVisits - a.totalVisits);

  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <title>تقرير أداء الحملة - ${escapeHtml(campaign.name)}</title>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;900&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Cairo', sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }
    .container { max-width: 900px; margin: 0 auto; background: #fff; min-height: 100vh; }
    .cover { background: linear-gradient(135deg, #14532d 0%, #15803d 50%, #b91c1c 100%); color: #fff; padding: 60px 40px; text-align: center; page-break-after: always; }
    .cover h1 { font-size: 32px; font-weight: 900; margin-bottom: 20px; }
    .cover h2 { font-size: 22px; font-weight: 700; margin-bottom: 30px; opacity: 0.95; }
    .cover .meta { font-size: 14px; opacity: 0.85; margin-top: 40px; }
    .cover .date { font-size: 13px; opacity: 0.75; margin-top: 10px; }
    .content { padding: 40px; }
    .section { margin-bottom: 30px; page-break-inside: avoid; }
    .section-title { font-size: 18px; font-weight: 700; color: #14532d; border-right: 4px solid #15803d; padding-right: 12px; margin-bottom: 16px; }
    .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 24px; }
    .stat-card { background: #f0fdf4; border: 1px solid #dcfce7; border-radius: 12px; padding: 16px; text-align: center; }
    .stat-value { font-size: 26px; font-weight: 900; color: #15803d; }
    .stat-label { font-size: 12px; color: #64748b; margin-top: 4px; }
    .info-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
    .info-table th, .info-table td { padding: 10px 12px; text-align: right; font-size: 13px; }
    .info-table th { background: #f0fdf4; color: #14532d; font-weight: 600; border-bottom: 2px solid #15803d; }
    .info-table td { border-bottom: 1px solid #e2e8f0; }
    .info-table tr:nth-child(even) td { background: #f8fafc; }
    .status-badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
    .status-active { background: #dcfce7; color: #15803d; }
    .status-ended { background: #fee2e2; color: #b91c1c; }
    .status-inactive { background: #f1f5f9; color: #64748b; }
    .footer { text-align: center; padding: 20px; font-size: 11px; color: #94a3b8; border-top: 1px solid #e2e8f0; margin-top: 40px; }
    .page-break { page-break-before: always; }
    .tweet-row { font-size: 12px; }
    .tweet-text { max-width: 400px; word-wrap: break-word; }
    @media print { body { background: #fff; } .container { max-width: 100%; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="cover">
      <h1>تقرير أداء الحملة الإعلامية</h1>
      <h2>${escapeHtml(campaign.name)}</h2>
      <div class="meta"><p>السعودية سبب الفتن</p><p>الحملة الإلكترونية الموحدة</p></div>
      <div class="date"><p>تاريخ إصدار التقرير: ${formatDateAr(now)}</p></div>
    </div>
    <div class="content">
      <div class="section">
        <h3 class="section-title">معلومات الحملة</h3>
        <table class="info-table">
          <tr><th style="width:30%">البيان</th><th>القيمة</th></tr>
          <tr><td>اسم الحملة</td><td><strong>${escapeHtml(campaign.name)}</strong></td></tr>
          ${campaign.description ? `<tr><td>المقدمة</td><td>${escapeHtml(campaign.description)}</td></tr>` : ''}
          <tr><td>تاريخ الإطلاق</td><td>${formatDateAr(campaign.target_time)}</td></tr>
          <tr><td>المنطقة الزمنية</td><td>${escapeHtml(campaign.timezone_label || 'Asia/Riyadh')}</td></tr>
          ${campaign.end_time ? `<tr><td>تاريخ الانتهاء</td><td>${formatDateAr(campaign.end_time)}</td></tr>` : ''}
          <tr><td>الحالة</td><td><span class="status-badge status-${statusText === 'نشطة' ? 'active' : statusText === 'منتهية' ? 'ended' : 'inactive'}">${statusText}</span></td></tr>
        </table>
      </div>
      <div class="section">
        <h3 class="section-title">الإحصائيات الرئيسية</h3>
        <div class="stats-grid">
          <div class="stat-card"><div class="stat-value">${campaignViews}</div><div class="stat-label">مشاهدات الحملة</div></div>
          <div class="stat-card"><div class="stat-value">${uniqueVisitors}</div><div class="stat-label">زوار فريدون</div></div>
          <div class="stat-card"><div class="stat-value">${(tweets || []).length}</div><div class="stat-label">عدد التغريدات</div></div>
          <div class="stat-card"><div class="stat-value">${mediaCount}</div><div class="stat-label">تغريدات بوسائط</div></div>
          <div class="stat-card"><div class="stat-value">${shareClicks}</div><div class="stat-label">ضغطات مشاركة</div></div>
          <div class="stat-card"><div class="stat-value">${copies}</div><div class="stat-label">عمليات نسخ</div></div>
          <div class="stat-card"><div class="stat-value">${imageSaves}</div><div class="stat-label">صور محفوظة</div></div>
        </div>
      </div>
      <div class="section">
        <h3 class="section-title">المشاركات حسب المنصة</h3>
        <div class="stats-grid">
          <div class="stat-card"><div class="stat-value">${platformStats.x}</div><div class="stat-label">X (تويتر)</div></div>
          <div class="stat-card"><div class="stat-value">${platformStats.whatsapp}</div><div class="stat-label">واتساب</div></div>
          <div class="stat-card"><div class="stat-value">${platformStats.facebook}</div><div class="stat-label">فيسبوك</div></div>
          <div class="stat-card"><div class="stat-value">${platformStats.telegram}</div><div class="stat-label">تيليجرام</div></div>
          <div class="stat-card"><div class="stat-value">${platformStats.native}</div><div class="stat-label">مشاركة أصلية</div></div>
        </div>
      </div>
      ${inviteStats.length > 0 ? `
      <div class="section">
        <h3 class="section-title">إحصائيات روابط الدعوة</h3>
        <table class="info-table">
          <tr><th>الرابط</th><th>الزيارات</th><th>الزوار الفريدون</th><th>المشاركات</th><th>آخر زيارة</th></tr>
          ${inviteStats.map(s => `
          <tr><td>${escapeHtml(s.name)} ${!s.isActive ? '<span style="color:#6b7280;font-size:11px">(معطل)</span>' : ''}</td><td><strong>${s.totalVisits}</strong></td><td>${s.uniqueVisitors}</td><td>${s.shareClicks}</td><td>${s.lastVisit ? formatDateAr(s.lastVisit) : '-'}</td></tr>
          `).join('')}
        </table>
      </div>` : ''}
      ${Object.keys(subAdminStats).length > 0 ? `
      <div class="section">
        <h3 class="section-title">أداء المشرفين الفرعيين</h3>
        <table class="info-table">
          <tr><th>المشرف</th><th>التغريدات المضافة</th><th>التغريدات المعدلة</th></tr>
          ${Object.values(subAdminStats).map(s => `<tr><td>${escapeHtml(s.name)}</td><td>${s.tweetsAdded}</td><td>${s.tweetsEdited}</td></tr>`).join('')}
        </table>
      </div>` : ''}
      ${(tweets || []).length > 0 ? `
      <div class="section page-break">
        <h3 class="section-title">قائمة التغريدات المنشورة (${(tweets || []).length})</h3>
        <table class="info-table">
          <tr><th>#</th><th>النص</th><th>الوسائط</th><th>تاريخ النشر</th></tr>
          ${(tweets || []).map((t, i) => `
          <tr class="tweet-row"><td style="width:30px">${i + 1}</td><td class="tweet-text">${escapeHtml(t.text || '').substring(0, 200)}${(t.text || '').length > 200 ? '...' : ''}</td><td style="width:60px;text-align:center">${t.media_url ? '✓' : '-'}</td><td style="width:140px">${formatDateAr(t.created_at)}</td></tr>
          `).join('')}
        </table>
      </div>` : ''}
      <div class="footer">
        <p>تقرير أداء الحملة الإعلامية - ${escapeHtml(campaign.name)}</p>
        <p>تم إنشاء هذا التقرير بواسطة نظام إدارة الحملات - ${formatDateAr(now)}</p>
      </div>
    </div>
  </div>
</body>
</html>`;
}

async function handleReport(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }
  if (req.method !== 'GET') {
    res.writeHead(405, corsHeaders);
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  const isMainAdmin = await validateMainAdmin(req);
  if (!isMainAdmin) {
    res.writeHead(403, corsHeaders);
    res.end(JSON.stringify({ error: 'Forbidden. Main admin access required.' }));
    return;
  }

  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const campaignId = url.searchParams.get('campaignId');
    const format = url.searchParams.get('format') || 'html';

    if (!campaignId) {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'campaignId is required' }));
      return;
    }

    const html = await generateReportHTML(campaignId);
    if (!html) {
      res.writeHead(404, corsHeaders);
      res.end(JSON.stringify({ error: 'Campaign not found' }));
      return;
    }

    if (format === 'html') {
      res.writeHead(200, { ...corsHeaders, 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } else if (format === 'pdf') {
      const printHtml = html.replace('</body>', `
  <script>
    window.onload = function() { setTimeout(function() { window.print(); }, 500); };
  </script>
</body>`);
      res.writeHead(200, { ...corsHeaders, 'Content-Type': 'text/html; charset=utf-8', 'Content-Disposition': `attachment; filename="campaign-report-${campaignId}.html"` });
      res.end(printHtml);
    } else {
      res.writeHead(400, corsHeaders);
      res.end(JSON.stringify({ error: 'Invalid format. Use html or pdf' }));
    }
  } catch (error) {
    console.error('Report error:', error.message);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: error.message || 'Internal error' }));
  }
}

// ============================================================================
// MAIN ROUTER
// ============================================================================

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  let path = url.pathname;

  path = path.replace(/\/+$/, '') || '/';

  try {
    // FACTORY ROUTES: /api/factory/...
    if (path.startsWith('/api/factory')) {
      let factoryPath = path.replace(/^\/api\/factory/, '') || '/';

      // Auth routes
      if (factoryPath === '/auth' && req.method === 'POST') {
        return await handleAuth(req, res);
      }
      if (factoryPath === '/me' && req.method === 'GET') {
        return await handleMe(req, res);
      }

      // Config (public for tenant sites)
      if (factoryPath === '/config' && req.method === 'GET') {
        return await handleConfig(req, res);
      }

      // Tenants CRUD
      if (factoryPath === '/tenants') {
        return await handleTenants(req, res);
      }

      // Tenant by ID
      const tenantMatch = factoryPath.match(/^\/tenants\/([a-f0-9-]+)$/);
      if (tenantMatch) {
        return await handleTenantById(req, res, tenantMatch[1]);
      }

      // Provisioning
      if (factoryPath === '/provision' && req.method === 'POST') {
        return await handleProvision(req, res);
      }

      // Provisioning step
      if (factoryPath === '/provision/step' && req.method === 'POST') {
        return await handleProvisionStep(req, res);
      }

      // File upload
      if (factoryPath === '/upload' && req.method === 'POST') {
        return await handleUpload(req, res);
      }

      // Activity logs
      if (factoryPath === '/logs' && req.method === 'GET') {
        return await handleLogs(req, res);
      }

      res.writeHead(404, corsHeaders);
      res.end(JSON.stringify({ error: 'Factory endpoint not found: ' + factoryPath }));
      return;
    }

    // TENANT ROUTES: /api/...
    if (path.startsWith('/api/')) {
      let tenantPath = path.replace(/^\/api/, '') || '/';

      if (tenantPath === '/auth' && req.method === 'POST') {
        return await handleTenantAuth(req, res);
      }
      if (tenantPath === '/config' && req.method === 'GET') {
        return await handleTenantConfig(req, res);
      }
      if (tenantPath === '/logout' && req.method === 'POST') {
        return await handleTenantLogout(req, res);
      }
      if (tenantPath === '/me' && req.method === 'GET') {
        return await handleTenantMe(req, res);
      }
      if (tenantPath === '/campaign') {
        return await handleCampaign(req, res);
      }
      if (tenantPath === '/update') {
        return await handleUpdate(req, res);
      }
      if (tenantPath === '/delete-campaign') {
        return await handleDeleteCampaign(req, res);
      }
      if (tenantPath === '/delete-tweet') {
        return await handleDeleteTweet(req, res);
      }
      if (tenantPath === '/sub-admins') {
        return await handleSubAdmins(req, res);
      }
      if (tenantPath === '/invite-links') {
        return await handleInviteLinks(req, res);
      }
      if (tenantPath === '/analytics') {
        return await handleAnalytics(req, res);
      }
      if (tenantPath === '/report') {
        return await handleReport(req, res);
      }

      res.writeHead(404, corsHeaders);
      res.end(JSON.stringify({ error: 'Tenant endpoint not found: ' + tenantPath }));
      return;
    }

    // 404 for anything else
    res.writeHead(404, corsHeaders);
    res.end(JSON.stringify({ error: 'Endpoint not found: ' + path }));
  } catch (error) {
    console.error('API error:', error);
    res.writeHead(500, corsHeaders);
    res.end(JSON.stringify({ error: 'Internal server error' }));
  }
};
