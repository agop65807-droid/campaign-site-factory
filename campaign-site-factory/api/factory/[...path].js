const {
  hashToken,
  generateToken,
  verifyPassword,
  encrypt,
  decrypt,
  generateSlug
} = require('../../lib/crypto');

const {
  generateTotpSecret,
  verifyTotp,
  buildOtpAuthUri
} = require('../../lib/totp');

const { factoryClient, tenantClientForTenant } = require('../../lib/supabase');
const { checkRateLimit } = require('../../lib/rate-limit');
const provisioning = require('../../lib/provisioning');
const domains = require('../../lib/domains');
const {
  loginSchema,
  tenantCreateSchema,
  tenantUpdateSchema,
  domainSchema
} = require('../../lib/validation');

const securityHeaders = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
};

function send(res, status, payload) {
  res.writeHead(status, securityHeaders);
  res.end(JSON.stringify(payload));
}

async function readJSON(req, limit = 100000) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > limit) {
        req.destroy();
        reject(new Error('Body too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function getIp(req) {
  return req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
}

function getUserAgent(req) {
  return req.headers['user-agent'] || 'unknown';
}

function getBearerToken(req) {
  const auth = req.headers.authorization || '';
  return auth.replace('Bearer ', '').trim();
}

async function logFactoryActivity(db, data) {
  try {
    await db.from('factory_activity_logs').insert({
      super_admin_id: data.superAdminId || null,
      tenant_id: data.tenantId || null,
      action_type: data.actionType,
      details: data.details || {},
      ip_address: data.ip || null,
      user_agent: data.userAgent || null
    });
  } catch (e) {
    console.error('Factory audit log error:', e.message);
  }
}

async function validateSuperAdmin(req) {
  const token = getBearerToken(req);
  if (!token || token.length < 32) return null;

  const db = factoryClient();
  const tokenHash = hashToken(token);

  const { data: session } = await db
    .from('super_admin_sessions')
    .select('*, super_admins(*)')
    .eq('session_token_hash', tokenHash)
    .is('revoked_at', null)
    .gt('expires_at', new Date().toISOString())
    .single();

  if (!session || !session.super_admins || !session.super_admins.is_active) {
    return null;
  }

  return {
    id: session.super_admins.id,
    username: session.super_admins.username
  };
}

async function createSession(db, adminId, hours = 8) {
  const token = generateToken();
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();

  const { error } = await db.from('super_admin_sessions').insert({
    session_token_hash: tokenHash,
    super_admin_id: adminId,
    expires_at: expiresAt
  });

  if (error) throw error;

  return { token, expiresAt };
}

async function handleLogin(req, res) {
  const db = factoryClient();
  const body = await readJSON(req);
  const parsed = loginSchema.safeParse(body);

  if (!parsed.success) {
    return send(res, 400, { error: 'Invalid input' });
  }

  const { username, password, totp_code } = parsed.data;
  const ip = getIp(req);

  const rate = await checkRateLimit(db, `factory_login:${username}:${ip}`, 5, 900);
  if (!rate.allowed) {
    return send(res, 429, { error: 'Too many attempts', retryAfter: rate.retryAfter });
  }

  const { data: admin } = await db
    .from('super_admins')
    .select('*')
    .eq('username', username)
    .eq('is_active', true)
    .single();

  if (!admin) {
    return send(res, 401, { error: 'Invalid credentials' });
  }

  if (admin.locked_until && new Date(admin.locked_until) > new Date()) {
    return send(res, 423, { error: 'Account temporarily locked' });
  }

  const passwordOk = verifyPassword(password, admin.password_hash, admin.password_salt);

  if (!passwordOk) {
    const attempts = (admin.failed_login_attempts || 0) + 1;
    const lock = attempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000).toISOString() : null;

    await db
      .from('super_admins')
      .update({
        failed_login_attempts: attempts,
        locked_until: lock,
        updated_at: new Date().toISOString()
      })
      .eq('id', admin.id);

    return send(res, 401, { error: 'Invalid credentials' });
  }

  await db
    .from('super_admins')
    .update({
      failed_login_attempts: 0,
      locked_until: null,
      last_login_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    })
    .eq('id', admin.id);

  if (admin.totp_enabled) {
    if (!totp_code) {
      return send(res, 401, { error: 'TOTP required', totp_required: true });
    }

    const secret = decrypt(admin.totp_secret_encrypted);
    if (!verifyTotp(secret, totp_code)) {
      return send(res, 401, { error: 'Invalid TOTP code' });
    }

    const session = await createSession(db, admin.id);
    await logFactoryActivity(db, {
      superAdminId: admin.id,
      actionType: 'login',
      ip,
      userAgent: getUserAgent(req)
    });

    return send(res, 200, {
      success: true,
      token: session.token,
      expiresAt: session.expiresAt,
      admin: { id: admin.id, username: admin.username }
    });
  }

  const require2fa = process.env.FACTORY_REQUIRE_2FA === 'true';

  if (require2fa) {
    let secretBase32;

    if (!admin.totp_secret_encrypted) {
      secretBase32 = generateTotpSecret();
      await db
        .from('super_admins')
        .update({
          totp_secret_encrypted: encrypt(secretBase32),
          updated_at: new Date().toISOString()
        })
        .eq('id', admin.id);
    } else {
      secretBase32 = decrypt(admin.totp_secret_encrypted);
    }

    const setupToken = encrypt(
      JSON.stringify({
        sub: admin.id,
        exp: Date.now() + 10 * 60 * 1000
      })
    );

    return send(res, 200, {
      totp_enrollment_required: true,
      secret: secretBase32,
      otpauth_uri: buildOtpAuthUri(secretBase32, admin.username),
      setup_token: setupToken
    });
  }

  const session = await createSession(db, admin.id);
  await logFactoryActivity(db, {
    superAdminId: admin.id,
    actionType: 'login',
    ip,
    userAgent: getUserAgent(req)
  });

  return send(res, 200, {
    success: true,
    token: session.token,
    expiresAt: session.expiresAt,
    admin: { id: admin.id, username: admin.username }
  });
}

async function handleTotpVerifySetup(req, res) {
  const db = factoryClient();
  const body = await readJSON(req);

  const setupToken = body.setup_token;
  const code = String(body.code || '').trim();

  if (!setupToken || !code) {
    return send(res, 400, { error: 'setup_token and code required' });
  }

  let payload;
  try {
    payload = JSON.parse(decrypt(setupToken));
  } catch {
    return send(res, 400, { error: 'Invalid setup token' });
  }

  if (!payload.sub || payload.exp < Date.now()) {
    return send(res, 400, { error: 'Setup token expired' });
  }

  const { data: admin } = await db
    .from('super_admins')
    .select('*')
    .eq('id', payload.sub)
    .single();

  if (!admin || !admin.totp_secret_encrypted) {
    return send(res, 400, { error: 'Invalid enrollment state' });
  }

  const secret = decrypt(admin.totp_secret_encrypted);
  if (!verifyTotp(secret, code)) {
    return send(res, 400, { error: 'Invalid TOTP code' });
  }

  await db
    .from('super_admins')
    .update({
      totp_enabled: true,
      must_enroll_totp: false,
      updated_at: new Date().toISOString()
    })
    .eq('id', admin.id);

  const session = await createSession(db, admin.id);

  await logFactoryActivity(db, {
    superAdminId: admin.id,
    actionType: 'totp_enrolled',
    ip: getIp(req),
    userAgent: getUserAgent(req)
  });

  return send(res, 200, {
    success: true,
    token: session.token,
    expiresAt: session.expiresAt
  });
}

async function handleMe(req, res) {
  const admin = await validateSuperAdmin(req);
  if (!admin) return send(res, 401, { error: 'Unauthorized' });
  return send(res, 200, { success: true, admin });
}

async function handleTenants(req, res) {
  const db = factoryClient();
  const admin = await validateSuperAdmin(req);
  if (!admin) return send(res, 401, { error: 'Unauthorized' });

  if (req.method === 'GET') {
    const { data: tenants } = await db
      .from('tenants')
      .select('*')
      .order('created_at', { ascending: false });

    return send(res, 200, { success: true, tenants: tenants || [] });
  }

  if (req.method === 'POST') {
    const body = await readJSON(req);
    const parsed = tenantCreateSchema.safeParse(body);

    if (!parsed.success) {
      return send(res, 400, { error: 'Invalid input', details: parsed.error.flatten() });
    }

    const data = parsed.data;
    let slug = data.slug || generateSlug(data.orgName);

    const { data: existing } = await db
      .from('tenants')
      .select('id')
      .eq('slug', slug)
      .single();

    if (existing) {
      slug = `${slug}-${Date.now().toString(36)}`;
    }

    const { data: settings } = await db
      .from('factory_settings')
      .select('*')
      .limit(1)
      .single();

    const insertPayload = {
      org_name: data.orgName,
      slug,
      description: data.description || '',
      hashtag: data.hashtag || '',
      primary_color: data.primaryColor || settings?.default_primary_color || '#15803d',
      secondary_color: data.secondaryColor || settings?.default_secondary_color || '#d97706',
      theme_mode: data.themeMode || settings?.default_theme_mode || 'dark',
      enabled_share_platforms: data.enabledSharePlatforms || settings?.default_enabled_share_platforms || ['x', 'whatsapp', 'facebook', 'telegram'],
      logo_url: data.logoUrl || '',
      favicon_url: data.faviconUrl || '',
      base_domain: settings?.base_domain || 'campaigns.example.com',
      status: 'creating',
      created_by: admin.id
    };

    const { data: tenant, error } = await db
      .from('tenants')
      .insert(insertPayload)
      .select()
      .single();

    if (error) {
      return send(res, 500, { error: error.message });
    }

    await logFactoryActivity(db, {
      superAdminId: admin.id,
      tenantId: tenant.id,
      actionType: 'create_tenant',
      details: { orgName: data.orgName, slug },
      ip: getIp(req),
      userAgent: getUserAgent(req)
    });

    return send(res, 200, { success: true, tenant });
  }

  return send(res, 405, { error: 'Method not allowed' });
}

async function handleTenantById(req, res, tenantId) {
  const db = factoryClient();
  const admin = await validateSuperAdmin(req);
  if (!admin) return send(res, 401, { error: 'Unauthorized' });

  const { data: tenant } = await db
    .from('tenants')
    .select('*')
    .eq('id', tenantId)
    .single();

  if (!tenant) return send(res, 404, { error: 'Tenant not found' });

  if (req.method === 'GET') {
    const { data: jobs } = await db
      .from('provisioning_jobs')
      .select('*')
      .eq('tenant_id', tenantId)
      .order('started_at', { ascending: false })
      .limit(20);

    const { data: tenantDomains } = await db
      .from('tenant_domains')
      .select('*')
      .eq('tenant_id', tenantId)
      .order('created_at', { ascending: false });

    return send(res, 200, {
      success: true,
      tenant,
      jobs: jobs || [],
      domains: tenantDomains || []
    });
  }

  if (req.method === 'PUT') {
    const body = await readJSON(req);
    const parsed = tenantUpdateSchema.safeParse(body);

    if (!parsed.success) {
      return send(res, 400, { error: 'Invalid input' });
    }

    const update = { updated_at: new Date().toISOString() };

    if (parsed.data.orgName !== undefined) update.org_name = parsed.data.orgName;
    if (parsed.data.description !== undefined) update.description = parsed.data.description;
    if (parsed.data.hashtag !== undefined) update.hashtag = parsed.data.hashtag;
    if (parsed.data.primaryColor !== undefined) update.primary_color = parsed.data.primaryColor;
    if (parsed.data.secondaryColor !== undefined) update.secondary_color = parsed.data.secondaryColor;
    if (parsed.data.themeMode !== undefined) update.theme_mode = parsed.data.themeMode;
    if (parsed.data.enabledSharePlatforms !== undefined) update.enabled_share_platforms = parsed.data.enabledSharePlatforms;
    if (parsed.data.logoUrl !== undefined) update.logo_url = parsed.data.logoUrl;
    if (parsed.data.faviconUrl !== undefined) update.favicon_url = parsed.data.faviconUrl;

    if (parsed.data.status === 'suspended') {
      update.status = 'suspended';
      update.suspended_at = new Date().toISOString();
    }

    if (parsed.data.status === 'active') {
      update.status = 'active';
      update.suspended_at = null;
    }

    const { data: updatedTenant, error } = await db
      .from('tenants')
      .update(update)
      .eq('id', tenantId)
      .select()
      .single();

    if (error) return send(res, 500, { error: error.message });

    if (updatedTenant.status === 'active' && updatedTenant.tenant_service_key_encrypted) {
      try {
        const tenantDb = tenantClientForTenant(updatedTenant);
        await tenantDb.rpc('upsert_site_settings', {
          p: {
            org_name: updatedTenant.org_name,
            hashtag: updatedTenant.hashtag,
            logo_url: updatedTenant.logo_url,
            favicon_url: updatedTenant.favicon_url,
            primary_color: updatedTenant.primary_color,
            secondary_color: updatedTenant.secondary_color,
            theme_mode: updatedTenant.theme_mode,
            enabled_share_platforms: updatedTenant.enabled_share_platforms,
            meta_title: updatedTenant.org_name,
            meta_description: updatedTenant.description
          }
        });
      } catch (e) {
        console.error('Tenant identity sync warning:', e.message);
      }
    }

    await logFactoryActivity(db, {
      superAdminId: admin.id,
      tenantId,
      actionType: 'update_tenant',
      details: { fields: Object.keys(update) },
      ip: getIp(req),
      userAgent: getUserAgent(req)
    });

    return send(res, 200, { success: true, tenant: updatedTenant });
  }

  if (req.method === 'DELETE') {
    await db
      .from('tenants')
      .update({
        status: 'deleting',
        deleted_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .eq('id', tenantId);

    await logFactoryActivity(db, {
      superAdminId: admin.id,
      tenantId,
      actionType: 'delete_tenant',
      details: { slug: tenant.slug },
      ip: getIp(req),
      userAgent: getUserAgent(req)
    });

    return send(res, 200, { success: true, message: 'Tenant marked for deletion' });
  }

  return send(res, 405, { error: 'Method not allowed' });
}

async function handleTenantDomains(req, res, tenantId) {
  const db = factoryClient();
  const admin = await validateSuperAdmin(req);
  if (!admin) return send(res, 401, { error: 'Unauthorized' });

  const { data: tenant } = await db
    .from('tenants')
    .select('*')
    .eq('id', tenantId)
    .single();

  if (!tenant) return send(res, 404, { error: 'Tenant not found' });

  if (req.method === 'POST') {
    const body = await readJSON(req);
    const parsed = domainSchema.safeParse(body);

    if (!parsed.success) {
      return send(res, 400, { error: 'Invalid hostname' });
    }

    try {
      const result = await domains.addTenantDomain({
        tenant,
        hostname: parsed.data.hostname,
        setPrimary: parsed.data.setPrimary || false
      });

      await logFactoryActivity(db, {
        superAdminId: admin.id,
        tenantId,
        actionType: 'add_domain',
        details: { hostname: parsed.data.hostname },
        ip: getIp(req),
        userAgent: getUserAgent(req)
      });

      return send(res, 200, result);
    } catch (e) {
      return send(res, 400, { error: e.message });
    }
  }

  return send(res, 405, { error: 'Method not allowed' });
}

async function handleTenantDomainById(req, res, tenantId, domainId) {
  const db = factoryClient();
  const admin = await validateSuperAdmin(req);
  if (!admin) return send(res, 401, { error: 'Unauthorized' });

  const { data: tenant } = await db
    .from('tenants')
    .select('*')
    .eq('id', tenantId)
    .single();

  if (!tenant) return send(res, 404, { error: 'Tenant not found' });

  if (req.method === 'DELETE') {
    try {
      await domains.removeTenantDomain({ tenant, domainId });

      await logFactoryActivity(db, {
        superAdminId: admin.id,
        tenantId,
        actionType: 'remove_domain',
        details: { domainId },
        ip: getIp(req),
        userAgent: getUserAgent(req)
      });

      return send(res, 200, { success: true });
    } catch (e) {
      return send(res, 400, { error: e.message });
    }
  }

  return send(res, 405, { error: 'Method not allowed' });
}

async function handleProvisionStart(req, res) {
  const db = factoryClient();
  const admin = await validateSuperAdmin(req);
  if (!admin) return send(res, 401, { error: 'Unauthorized' });

  const body = await readJSON(req);
  const tenantId = body.tenantId;
  const adminUsername = body.adminUsername;
  const adminPassword = body.adminPassword;

  if (!tenantId) return send(res, 400, { error: 'tenantId required' });

  const { data: tenant } = await db
    .from('tenants')
    .select('*')
    .eq('id', tenantId)
    .single();

  if (!tenant) return send(res, 404, { error: 'Tenant not found' });

  const { data: job, error } = await db
    .from('provisioning_jobs')
    .insert({
      tenant_id: tenantId,
      step: 'init',
      status: 'running',
      created_by: admin.id
    })
    .select()
    .single();

  if (error) return send(res, 500, { error: error.message });

  const result = await provisioning.provisionStep(tenant, job.id, {
    adminUsername,
    adminPassword
  });

  await logFactoryActivity(db, {
    superAdminId: admin.id,
    tenantId,
    actionType: 'provision_start',
    details: { jobId: job.id },
    ip: getIp(req),
    userAgent: getUserAgent(req)
  });

  return send(res, 200, { ...result, jobId: job.id });
}

async function handleProvisionStep(req, res) {
  const db = factoryClient();
  const admin = await validateSuperAdmin(req);
  if (!admin) return send(res, 401, { error: 'Unauthorized' });

  const body = await readJSON(req);
  const jobId = body.jobId;
  const adminUsername = body.adminUsername;
  const adminPassword = body.adminPassword;

  if (!jobId) return send(res, 400, { error: 'jobId required' });

  const { data: job } = await db
    .from('provisioning_jobs')
    .select('*')
    .eq('id', jobId)
    .single();

  if (!job) return send(res, 404, { error: 'Job not found' });

  const { data: tenant } = await db
    .from('tenants')
    .select('*')
    .eq('id', job.tenant_id)
    .single();

  if (!tenant) return send(res, 404, { error: 'Tenant not found' });

  const result = await provisioning.provisionStep(tenant, job.id, {
    adminUsername,
    adminPassword
  });

  return send(res, 200, result);
}

async function handleLogs(req, res) {
  const db = factoryClient();
  const admin = await validateSuperAdmin(req);
  if (!admin) return send(res, 401, { error: 'Unauthorized' });

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10), 500);
  const tenantId = url.searchParams.get('tenantId');

  let query = db.from('factory_activity_logs').select('*');

  if (tenantId) {
    query = query.eq('tenant_id', tenantId);
  }

  const { data: logs } = await query
    .order('created_at', { ascending: false })
    .limit(limit);

  return send(res, 200, { success: true, logs: logs || [] });
}

module.exports = async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const path = url.pathname.replace(/^\/api\/factory/, '') || '/';

  if (req.method === 'OPTIONS') {
    res.writeHead(204, securityHeaders);
    res.end();
    return;
  }

  try {
    if (path === '/auth/login' && req.method === 'POST') {
      return await handleLogin(req, res);
    }

    if (path === '/auth/totp/verify-setup' && req.method === 'POST') {
      return await handleTotpVerifySetup(req, res);
    }

    if (path === '/me' && req.method === 'GET') {
      return await handleMe(req, res);
    }

    if (path === '/tenants') {
      return await handleTenants(req, res);
    }

    const tenantMatch = path.match(/^\/tenants\/([a-f0-9-]+)$/);
    if (tenantMatch) {
      return await handleTenantById(req, res, tenantMatch[1]);
    }

    const domainsMatch = path.match(/^\/tenants\/([a-f0-9-]+)\/domains$/);
    if (domainsMatch) {
      return await handleTenantDomains(req, res, domainsMatch[1]);
    }

    const domainByIdMatch = path.match(/^\/tenants\/([a-f0-9-]+)\/domains\/([a-f0-9-]+)$/);
    if (domainByIdMatch) {
      return await handleTenantDomainById(req, res, domainByIdMatch[1], domainByIdMatch[2]);
    }

    if (path === '/provision/start' && req.method === 'POST') {
      return await handleProvisionStart(req, res);
    }

    if (path === '/provision/step' && req.method === 'POST') {
      return await handleProvisionStep(req, res);
    }

    if (path === '/logs' && req.method === 'GET') {
      return await handleLogs(req, res);
    }

    return send(res, 404, { error: 'Not found' });
  } catch (error) {
    console.error('Factory API error:', error);
    return send(res, 500, { error: 'Internal server error' });
  }
};
