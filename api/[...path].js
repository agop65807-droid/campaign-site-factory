const {
  hashToken,
  generateToken,
  generateSalt,
  hashPassword,
  verifyPasswordAsync
} = require('../lib/crypto');

const { tenantClient } = require('../lib/supabase');
const { resolveTenant } = require('../lib/tenant-resolver');
const factoryHandler = require('./factory/[...path].js');

const corsHeaders = {
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
};

const SESSION_EXPIRY_HOURS = 24;
const RATE_LIMIT_MAX = 15;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const rateLimitStore = new Map();

function getClientIdentifier(req) {
  const ip = getIpAddress(req);
  const ua = req.headers['user-agent'] || 'unknown';
  return require('crypto').createHash('sha256').update(ip + ua).digest('hex').slice(0, 32);
}

function checkRateLimit(identifier, maxAttempts = RATE_LIMIT_MAX) {
  const now = Date.now();
  if (rateLimitStore.size > 5000) {
    for (const [key, val] of rateLimitStore.entries()) {
      if (now - val.firstAttempt > RATE_LIMIT_WINDOW) rateLimitStore.delete(key);
    }
  }
  const record = rateLimitStore.get(identifier);
  if (!record) {
    rateLimitStore.set(identifier, { count: 1, firstAttempt: now });
    return { allowed: true, remaining: maxAttempts - 1 };
  }
  if (now - record.firstAttempt > RATE_LIMIT_WINDOW) {
    rateLimitStore.set(identifier, { count: 1, firstAttempt: now });
    return { allowed: true, remaining: maxAttempts - 1 };
  }
  if (record.count >= maxAttempts) {
    const retryAfter = Math.ceil((RATE_LIMIT_WINDOW - (now - record.firstAttempt)) / 1000);
    return { allowed: false, remaining: 0, retryAfter };
  }
  record.count++;
  return { allowed: true, remaining: maxAttempts - record.count };
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input.replace(/[<>"'&]/g, '').trim();
}

function sanitizeText(text) {
  if (typeof text !== 'string') return '';
  return text.replace(/[<>]/g, '').trim();
}

function validateUrl(url) {
  if (!url || typeof url !== 'string') return null;
  const trimmed = url.trim();
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) return null;
  if (trimmed.length > 2000) return null;
  try { new URL(trimmed); return trimmed; } catch { return null; }
}

function getIpAddress(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return (forwarded || req.socket?.remoteAddress || 'unknown').slice(0, 64);
}

function getUserAgent(req) {
  return req.headers['user-agent'] || 'unknown';
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatDateAr(dateStr) {
  if (!dateStr) return '-';
  try {
    return new Date(dateStr).toLocaleString('ar-SA', {
      year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit'
    });
  } catch { return dateStr; }
}

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

let _supabase = null;
function getSupabase() {
  if (!_supabase) {
    _supabase = tenantClient();
  }
  return _supabase;
}

async function getScopedCampaign(campaignId, tenantId, activeOnly = false) {
  if (!campaignId) return null;
  let query = getSupabase()
    .from('campaigns')
    .select('id, is_active')
    .eq('id', campaignId);
  if (tenantId) query = query.eq('tenant_id', tenantId);
  if (activeOnly) query = query.eq('is_active', true);
  const { data } = await query.maybeSingle();
  return data || null;
}

async function logActivity(data, tenantId = null) {
  try {
    const payload = {
      admin_type: data.adminType,
      sub_admin_id: data.subAdminId || null,
      admin_name: data.adminName || null,
      action_type: data.actionType,
      campaign_id: data.campaignId || null,
      tweet_id: data.tweetId || null,
      details: data.details || {},
      ip_address: data.ip || null,
      user_agent: data.userAgent || null
    };
    if (tenantId) payload.tenant_id = tenantId;
    await getSupabase().from('admin_activity_logs').insert(payload);
  } catch (e) {
    console.error('Activity log error:', e.message);
  }
}

async function validateSession(req, tenantId = null) {
  const authHeader = req.headers.authorization || '';
  const token = sanitizeInput(authHeader.replace('Bearer ', '').trim());
  if (!token || token.length < 32) return null;

  const tokenHash = hashToken(token);
  let query = getSupabase()
    .from('admin_sessions')
    .select('*, sub_admins(*)')
    .eq('session_token_hash', tokenHash)
    .is('revoked_at', null)
    .gt('expires_at', new Date().toISOString());

  if (tenantId) {
    query = query.eq('tenant_id', tenantId);
  }

  const { data: session } = await query.single();
  if (!session) return null;

  if (session.admin_type === 'main') {
    let mainAdminQuery = getSupabase()
      .from('main_admins')
      .select('id, username, is_active')
      .eq('is_active', true)
      .limit(1);
    if (tenantId) mainAdminQuery = mainAdminQuery.eq('tenant_id', tenantId);
    const { data: mainAdmin } = await mainAdminQuery.maybeSingle();
    if (!mainAdmin) return null;

    return {
      adminType: 'main',
      name: mainAdmin.username || 'المشرف الرئيسي',
      subAdminId: null,
      tenantId: session.tenant_id || tenantId,
      permissions: {
        canCreateCampaign: true, canEditCampaign: true, canDeleteCampaign: true,
        canAddTweets: true, canEditTweets: true, canDeleteTweets: true,
        canImportExcel: true, canCreateSubAdmin: true, canViewReports: true,
        canCreateInvite: true, canViewAnalytics: true
      }
    };
  }

  if (session.sub_admins && session.sub_admins.is_active) {
    return {
      adminType: 'sub',
      subAdminId: session.sub_admin_id,
      name: session.sub_admins.name,
      tenantId: session.tenant_id || tenantId,
      permissions: session.sub_admins.permissions || {}
    };
  }

  return null;
}

async function handleTenantAuth(req, res, tenantId) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }
  if (req.method !== 'POST') {
    res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' })); return;
  }

  const clientId = getClientIdentifier(req);
  const rateCheck = checkRateLimit(clientId);
  if (!rateCheck.allowed) {
    res.writeHead(429, { ...corsHeaders, 'Retry-After': String(rateCheck.retryAfter) });
    res.end(JSON.stringify({ error: 'Too many login attempts', retryAfter: rateCheck.retryAfter }));
    return;
  }

  try {
    const body = await readBody(req, 10000);
    const data = JSON.parse(body || '{}');
    let { username, password } = data;
    username = sanitizeInput(username);
    password = sanitizeInput(password);

    if (!username || !password) {
      res.writeHead(400, corsHeaders); res.end(JSON.stringify({ error: 'Username and password required' })); return;
    }

    let authResult = null;

    let mainQuery = getSupabase().from('main_admins').select('*').eq('username', username).eq('is_active', true);
    if (tenantId) mainQuery = mainQuery.eq('tenant_id', tenantId);
    const { data: mainAdmin } = await mainQuery.single();

    if (mainAdmin) {
      if (mainAdmin.locked_until && new Date(mainAdmin.locked_until) > new Date()) {
        res.writeHead(423, corsHeaders); res.end(JSON.stringify({ error: 'Account temporarily locked' })); return;
      }

      const passwordOk = await verifyPasswordAsync(password, mainAdmin.password_hash, mainAdmin.password_salt);

      if (!passwordOk) {
        const attempts = (mainAdmin.failed_login_attempts || 0) + 1;
        const lock = attempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000).toISOString() : null;
        await getSupabase().from('main_admins').update({
          failed_login_attempts: attempts, locked_until: lock, updated_at: new Date().toISOString()
        }).eq('id', mainAdmin.id);
        res.writeHead(401, corsHeaders); res.end(JSON.stringify({ error: 'Invalid credentials' })); return;
      }

      await getSupabase().from('main_admins').update({
        failed_login_attempts: 0, locked_until: null, last_login_at: new Date().toISOString(), updated_at: new Date().toISOString()
      }).eq('id', mainAdmin.id);

      authResult = { success: true, adminType: 'main', name: 'المشرف الرئيسي', mustChangePassword: mainAdmin.must_change_password };
    }

    if (!authResult) {
      let subQuery = getSupabase().from('sub_admins').select('*').eq('username', username).eq('is_active', true);
      if (tenantId) subQuery = subQuery.eq('tenant_id', tenantId);
      const { data: subAdmin } = await subQuery.single();

      if (subAdmin) {
        const passwordOk = await verifyPasswordAsync(password, subAdmin.password_hash, subAdmin.password_salt);
        if (passwordOk) {
          await getSupabase().from('sub_admins').update({ last_login_at: new Date().toISOString() }).eq('id', subAdmin.id);
          authResult = { success: true, adminType: 'sub', subAdminId: subAdmin.id, name: subAdmin.name, permissions: subAdmin.permissions };
        }
      }
    }

    if (!authResult) {
      res.writeHead(401, corsHeaders); res.end(JSON.stringify({ error: 'Invalid credentials' })); return;
    }

    rateLimitStore.delete(clientId);

    const token = generateToken();
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + SESSION_EXPIRY_HOURS * 60 * 60 * 1000).toISOString();

    const sessObj = {
      session_token_hash: tokenHash, admin_type: authResult.adminType,
      sub_admin_id: authResult.subAdminId || null, expires_at: expiresAt
    };
    if (tenantId) sessObj.tenant_id = tenantId;

    const { error: sessErr } = await getSupabase().from('admin_sessions').insert(sessObj);

    if (sessErr) { res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: 'Failed to create session' })); return; }

    await logActivity({
      adminType: authResult.adminType, subAdminId: authResult.subAdminId || null,
      adminName: authResult.name, actionType: 'login', ip: getIpAddress(req), userAgent: getUserAgent(req)
    }, tenantId);

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({
      success: true, token, expiresAt, adminType: authResult.adminType, name: authResult.name,
      permissions: authResult.permissions || null, mustChangePassword: authResult.mustChangePassword || false
    }));
  } catch (error) {
    console.error('Tenant auth error:', error.message);
    res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: 'Internal server error' }));
  }
}

async function handleChangePassword(req, res, tenantId) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }
  if (req.method !== 'POST') { res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }

  const user = await validateSession(req, tenantId);
  if (!user) { res.writeHead(401, corsHeaders); res.end(JSON.stringify({ error: 'Unauthorized' })); return; }

  try {
    const body = await readBody(req, 10000);
    const { oldPassword, newPassword } = JSON.parse(body || '{}');

    if (!newPassword || newPassword.length < 10) {
      res.writeHead(400, corsHeaders); res.end(JSON.stringify({ error: 'New password must be at least 10 characters' })); return;
    }

    const salt = generateSalt();
    const hash = hashPassword(newPassword, salt);

    if (user.adminType === 'main') {
      let mainQuery = getSupabase().from('main_admins').select('*').limit(1);
      if (tenantId) mainQuery = mainQuery.eq('tenant_id', tenantId);
      const { data: mainAdmin } = await mainQuery.single();

      if (!mainAdmin) { res.writeHead(404, corsHeaders); res.end(JSON.stringify({ error: 'Main admin not found' })); return; }

      const oldOk = await verifyPasswordAsync(oldPassword || '', mainAdmin.password_hash, mainAdmin.password_salt);
      if (!oldOk && !mainAdmin.must_change_password) {
        res.writeHead(401, corsHeaders); res.end(JSON.stringify({ error: 'Old password is incorrect' })); return;
      }

      await getSupabase().from('main_admins').update({
        password_hash: hash, password_salt: salt, must_change_password: false,
        password_changed_at: new Date().toISOString(), updated_at: new Date().toISOString()
      }).eq('id', mainAdmin.id);
    } else {
      let subQuery = getSupabase().from('sub_admins').update({
        password_hash: hash, password_salt: salt, updated_at: new Date().toISOString()
      }).eq('id', user.subAdminId);
      if (tenantId) subQuery = subQuery.eq('tenant_id', tenantId);
      await subQuery;
    }

    await logActivity({
      adminType: user.adminType, subAdminId: user.subAdminId || null, adminName: user.name,
      actionType: 'change_password', ip: getIpAddress(req), userAgent: getUserAgent(req)
    }, tenantId);

    res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true }));
  } catch (error) {
    console.error('Change password error:', error.message);
    res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: 'Internal server error' }));
  }
}

async function handleTenantIdentity(req, res, tenantId) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }
  const user = await validateSession(req, tenantId);

  if (req.method === 'GET') {
    let query = getSupabase().from('site_settings').select('*').limit(1);
    if (tenantId) query = query.eq('tenant_id', tenantId);
    const { data: settings } = await query.single();
    res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, settings }));
    return;
  }

  if (req.method === 'PUT') {
    if (!user || user.adminType !== 'main') { res.writeHead(403, corsHeaders); res.end(JSON.stringify({ error: 'Main admin required' })); return; }

    let query = getSupabase().from('site_settings').select('*').limit(1);
    if (tenantId) query = query.eq('tenant_id', tenantId);
    const { data: current } = await query.single();
    if (!current?.allow_admin_identity_edit) { res.writeHead(403, corsHeaders); res.end(JSON.stringify({ error: 'Identity editing is controlled by factory' })); return; }

    const body = await readBody(req, 20000);
    const data = JSON.parse(body || '{}');
    const update = { updated_at: new Date().toISOString() };

    if (data.orgName) update.org_name = sanitizeText(data.orgName);
    if (data.hashtag !== undefined) update.hashtag = sanitizeText(data.hashtag);
    if (data.logoUrl) update.logo_url = validateUrl(data.logoUrl) || current.logo_url;
    if (data.faviconUrl) update.favicon_url = validateUrl(data.faviconUrl) || current.favicon_url;
    if (data.primaryColor) update.primary_color = data.primaryColor;
    if (data.secondaryColor) update.secondary_color = data.secondaryColor;
    if (data.themeMode) update.theme_mode = data.themeMode;
    if (data.enabledSharePlatforms) update.enabled_share_platforms = data.enabledSharePlatforms;
    if (data.metaTitle !== undefined) update.meta_title = sanitizeText(data.metaTitle);
    if (data.metaDescription !== undefined) update.meta_description = sanitizeText(data.metaDescription);

    const { data: updated, error } = await getSupabase().from('site_settings').update(update).eq('id', current.id).select().single();
    if (error) { res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: error.message })); return; }

    await logActivity({
      adminType: user.adminType, adminName: user.name, actionType: 'update_identity',
      details: { fields: Object.keys(update) }, ip: getIpAddress(req), userAgent: getUserAgent(req)
    }, tenantId);

    res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, settings: updated }));
    return;
  }

  res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' }));
}

async function handleConfig(req, res, tenantId) {
  let settingsQuery = getSupabase().from('site_settings').select('*').limit(1);
  if (tenantId) settingsQuery = settingsQuery.eq('tenant_id', tenantId);
  const { data: settings } = await settingsQuery.single();

  let campaignsQuery = getSupabase().from('campaigns').select('id, name, is_active').eq('is_active', true).order('created_at', { ascending: false }).limit(10);
  if (tenantId) campaignsQuery = campaignsQuery.eq('tenant_id', tenantId);
  const { data: campaigns } = await campaignsQuery;

  res.writeHead(200, corsHeaders);
  res.end(JSON.stringify({
    success: true,
    orgName: settings?.org_name || 'الحملة',
    orgDescription: settings?.meta_description || '',
    logoUrl: settings?.logo_url || '/logo-dark.png',
    faviconUrl: settings?.favicon_url || '/favicon.ico',
    hashtag: settings?.hashtag || '',
    primaryColor: settings?.primary_color || '#15803d',
    secondaryColor: settings?.secondary_color || '#d97706',
    themeMode: settings?.theme_mode || 'dark',
    enabledSharePlatforms: settings?.enabled_share_platforms || ['x', 'whatsapp', 'facebook', 'telegram'],
    metaTitle: settings?.meta_title || settings?.org_name || 'الحملة',
    metaDescription: settings?.meta_description || '',
    socialLinks: settings?.social_links || {},
    campaigns: campaigns || []
  }));
}

async function handleTenantMe(req, res, tenantId) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }
  const user = await validateSession(req, tenantId);
  if (!user) { res.writeHead(401, corsHeaders); res.end(JSON.stringify({ error: 'Unauthorized' })); return; }
  res.writeHead(200, corsHeaders);
  res.end(JSON.stringify({ success: true, user }));
}

async function handleTenantLogout(req, res, tenantId) {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }
  const authHeader = req.headers.authorization || '';
  const token = sanitizeInput(authHeader.replace('Bearer ', '').trim());
  if (token && token.length >= 32) {
    const tokenHash = hashToken(token);
    let query = getSupabase().from('admin_sessions').update({ revoked_at: new Date().toISOString() }).eq('session_token_hash', tokenHash);
    if (tenantId) query = query.eq('tenant_id', tenantId);
    await query;
  }
  res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true }));
}

async function handleCampaign(req, res, tenantId) {
  const user = await validateSession(req, tenantId);
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const campaignId = url.searchParams.get('id');

  if (campaignId) {
    let cmpQuery = getSupabase().from('campaigns').select('*').eq('id', campaignId);
    if (tenantId) cmpQuery = cmpQuery.eq('tenant_id', tenantId);
    if (!user) cmpQuery = cmpQuery.eq('is_active', true);
    const { data: campaign } = await cmpQuery.single();
    if (!campaign) {
      res.writeHead(404, corsHeaders);
      res.end(JSON.stringify({ error: 'Campaign not found' }));
      return;
    }

    let tweetsQuery = getSupabase().from('tweets').select('*').eq('campaign_id', campaignId).order('created_at', { ascending: true });
    if (tenantId) tweetsQuery = tweetsQuery.eq('tenant_id', tenantId);
    const { data: tweets } = await tweetsQuery;

    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({ success: true, campaign, tweets: tweets || [] }));
    return;
  }

  let campaignsQuery = getSupabase().from('campaigns').select('*').order('created_at', { ascending: false });
  if (tenantId) campaignsQuery = campaignsQuery.eq('tenant_id', tenantId);
  if (!user) campaignsQuery = campaignsQuery.eq('is_active', true);
  const { data: campaigns } = await campaignsQuery;

  res.writeHead(200, corsHeaders);
  res.end(JSON.stringify({ success: true, campaigns: campaigns || [] }));
}

async function handleUpdate(req, res, tenantId) {
  if (req.method !== 'POST') { res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }
  const user = await validateSession(req, tenantId);
  if (!user) { res.writeHead(401, corsHeaders); res.end(JSON.stringify({ error: 'Unauthorized' })); return; }

  const body = await readBody(req);
  const data = JSON.parse(body || '{}');

  if (data.type === 'campaign') {
    if (data.campaignId) {
      if (!user.permissions.canEditCampaign) { res.writeHead(403, corsHeaders); res.end(JSON.stringify({ error: 'Permission denied: canEditCampaign' })); return; }
      const update = { name: data.campaignName, description: data.description || '', video_url: data.videoUrl || null, hashtag: data.hashtag || '', target_time: data.targetTime, end_time: data.endTime || null, target_timezone: data.targetTimezone || 'Asia/Riyadh', timezone_label: data.timezoneLabel || 'توقيت مكة المكرمة (GMT+3)', is_active: data.isActive !== false, updated_at: new Date().toISOString() };
      let query = getSupabase().from('campaigns').update(update).eq('id', data.campaignId);
      if (tenantId) query = query.eq('tenant_id', tenantId);
      const { data: updated, error } = await query.select().single();
      if (error) { res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: error.message })); return; }
      await logActivity({ adminType: user.adminType, subAdminId: user.subAdminId, adminName: user.name, actionType: 'edit_campaign', campaignId: data.campaignId, ip: getIpAddress(req), userAgent: getUserAgent(req) }, tenantId);
      res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, campaign: updated }));
    } else {
      if (!user.permissions.canCreateCampaign) { res.writeHead(403, corsHeaders); res.end(JSON.stringify({ error: 'Permission denied: canCreateCampaign' })); return; }
      const insertObj = { name: data.campaignName, description: data.description || '', video_url: data.videoUrl || null, hashtag: data.hashtag || '', target_time: data.targetTime, end_time: data.endTime || null, target_timezone: data.targetTimezone || 'Asia/Riyadh', timezone_label: data.timezoneLabel || 'توقيت مكة المكرمة (GMT+3)', is_active: data.isActive !== false };
      if (tenantId) insertObj.tenant_id = tenantId;
      const { data: created, error } = await getSupabase().from('campaigns').insert(insertObj).select().single();
      if (error) { res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: error.message })); return; }
      await logActivity({ adminType: user.adminType, subAdminId: user.subAdminId, adminName: user.name, actionType: 'create_campaign', campaignId: created.id, ip: getIpAddress(req), userAgent: getUserAgent(req) }, tenantId);
      res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, campaign: created }));
    }
    return;
  }

  if (data.type === 'tweet') {
    if (data.tweetId) {
      if (!user.permissions.canEditTweets) { res.writeHead(403, corsHeaders); res.end(JSON.stringify({ error: 'Permission denied: canEditTweets' })); return; }
      let query = getSupabase().from('tweets').update({ title: data.tweetTitle || '', text: data.tweetText, media_url: data.mediaUrl || null, updated_at: new Date().toISOString() }).eq('id', data.tweetId);
      if (tenantId) query = query.eq('tenant_id', tenantId);
      const { data: updated, error } = await query.select().single();
      if (error) { res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: error.message })); return; }
      await logActivity({ adminType: user.adminType, subAdminId: user.subAdminId, adminName: user.name, actionType: 'edit_tweet', tweetId: data.tweetId, ip: getIpAddress(req), userAgent: getUserAgent(req) }, tenantId);
      res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, tweet: updated }));
    } else {
      if (!user.permissions.canAddTweets) { res.writeHead(403, corsHeaders); res.end(JSON.stringify({ error: 'Permission denied: canAddTweets' })); return; }
      const campaign = await getScopedCampaign(data.campaignId, tenantId);
      if (!campaign) { res.writeHead(404, corsHeaders); res.end(JSON.stringify({ error: 'Campaign not found' })); return; }
      const insertObj = { campaign_id: data.campaignId, title: data.tweetTitle || '', text: data.tweetText, media_url: data.mediaUrl || null, created_by_type: user.adminType, created_by_sub_admin_id: user.subAdminId };
      if (tenantId) insertObj.tenant_id = tenantId;
      const { data: created, error } = await getSupabase().from('tweets').insert(insertObj).select().single();
      if (error) { res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: error.message })); return; }
      await logActivity({ adminType: user.adminType, subAdminId: user.subAdminId, adminName: user.name, actionType: 'add_tweet', tweetId: created.id, ip: getIpAddress(req), userAgent: getUserAgent(req) }, tenantId);
      res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, tweet: created }));
    }
    return;
  }

  if (data.type === 'excel_import') {
    if (!user.permissions.canImportExcel) { res.writeHead(403, corsHeaders); res.end(JSON.stringify({ error: 'Permission denied: canImportExcel' })); return; }
    const campaign = await getScopedCampaign(data.campaignId, tenantId);
    if (!campaign) { res.writeHead(404, corsHeaders); res.end(JSON.stringify({ error: 'Campaign not found' })); return; }
    const tweets = (data.tweets || []).filter(t => t.text && t.text.length <= 280);
    const rows = tweets.map(t => {
      const obj = { campaign_id: data.campaignId, title: (t.title || '').substring(0, 100), text: t.text, media_url: t.media_url || null, created_by_type: user.adminType, created_by_sub_admin_id: user.subAdminId };
      if (tenantId) obj.tenant_id = tenantId;
      return obj;
    });
    if (rows.length === 0) { res.writeHead(400, corsHeaders); res.end(JSON.stringify({ error: 'No valid tweets found' })); return; }
    const { error } = await getSupabase().from('tweets').insert(rows);
    if (error) { res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: error.message })); return; }
    await logActivity({ adminType: user.adminType, subAdminId: user.subAdminId, adminName: user.name, actionType: 'import_excel', campaignId: data.campaignId, details: { count: rows.length }, ip: getIpAddress(req), userAgent: getUserAgent(req) }, tenantId);
    res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, count: rows.length }));
    return;
  }

  res.writeHead(400, corsHeaders); res.end(JSON.stringify({ error: 'Invalid type' }));
}

async function handleDeleteCampaign(req, res, tenantId) {
  if (req.method !== 'POST') { res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }
  const user = await validateSession(req, tenantId);
  if (!user || !user.permissions.canDeleteCampaign) { res.writeHead(403, corsHeaders); res.end(JSON.stringify({ error: 'Forbidden' })); return; }
  const body = await readBody(req);
  const { id } = JSON.parse(body || '{}');
  if (!id) { res.writeHead(400, corsHeaders); res.end(JSON.stringify({ error: 'ID required' })); return; }
  let query = getSupabase().from('campaigns').delete().eq('id', id);
  if (tenantId) query = query.eq('tenant_id', tenantId);
  await query;
  await logActivity({ adminType: user.adminType, adminName: user.name, actionType: 'delete_campaign', campaignId: id, ip: getIpAddress(req), userAgent: getUserAgent(req) }, tenantId);
  res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true }));
}

async function handleDeleteTweet(req, res, tenantId) {
  if (req.method !== 'POST') { res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }
  const user = await validateSession(req, tenantId);
  if (!user || !user.permissions.canDeleteTweets) { res.writeHead(403, corsHeaders); res.end(JSON.stringify({ error: 'Forbidden: canDeleteTweets' })); return; }
  const body = await readBody(req);
  const { id } = JSON.parse(body || '{}');
  if (!id) { res.writeHead(400, corsHeaders); res.end(JSON.stringify({ error: 'ID required' })); return; }
  let query = getSupabase().from('tweets').delete().eq('id', id);
  if (tenantId) query = query.eq('tenant_id', tenantId);
  await query;
  await logActivity({ adminType: user.adminType, subAdminId: user.subAdminId, adminName: user.name, actionType: 'delete_tweet', tweetId: id, ip: getIpAddress(req), userAgent: getUserAgent(req) }, tenantId);
  res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true }));
}

async function handleSubAdmins(req, res, tenantId) {
  const user = await validateSession(req, tenantId);
  if (!user || user.adminType !== 'main') { res.writeHead(403, corsHeaders); res.end(JSON.stringify({ error: 'Forbidden' })); return; }

  if (req.method === 'GET') {
    let query = getSupabase().from('sub_admins').select('*').order('created_at', { ascending: false });
    if (tenantId) query = query.eq('tenant_id', tenantId);
    const { data: subAdmins } = await query;
    res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, subAdmins: subAdmins || [] }));
    return;
  }

  if (req.method === 'POST') {
    const body = await readBody(req);
    const data = JSON.parse(body || '{}');
    const salt = generateSalt();
    const hash = hashPassword(data.password, salt);
    const insertObj = { name: data.name, username: data.username, password_hash: hash, password_salt: salt, permissions: data.permissions };
    if (tenantId) insertObj.tenant_id = tenantId;
    const { data: created, error } = await getSupabase().from('sub_admins').insert(insertObj).select().single();
    if (error) { res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: error.message })); return; }
    await logActivity({ adminType: 'main', adminName: user.name, actionType: 'create_sub_admin', details: { username: data.username }, ip: getIpAddress(req), userAgent: getUserAgent(req) }, tenantId);
    res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, subAdmin: created }));
    return;
  }

  if (req.method === 'PUT') {
    const body = await readBody(req);
    const data = JSON.parse(body || '{}');
    const update = { name: data.name, permissions: data.permissions, updated_at: new Date().toISOString() };
    if (data.password) { const salt = generateSalt(); update.password_hash = hashPassword(data.password, salt); update.password_salt = salt; }
    if (data.isActive !== undefined) update.is_active = data.isActive;
    let query = getSupabase().from('sub_admins').update(update).eq('id', data.id);
    if (tenantId) query = query.eq('tenant_id', tenantId);
    const { data: updated, error } = await query.select().single();
    if (error) { res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: error.message })); return; }
    await logActivity({ adminType: 'main', adminName: user.name, actionType: 'edit_sub_admin', details: { id: data.id }, ip: getIpAddress(req), userAgent: getUserAgent(req) }, tenantId);
    res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, subAdmin: updated }));
    return;
  }

  if (req.method === 'DELETE') {
    const body = await readBody(req);
    const { id } = JSON.parse(body || '{}');
    let query = getSupabase().from('sub_admins').update({ is_active: false }).eq('id', id);
    if (tenantId) query = query.eq('tenant_id', tenantId);
    await query;
    await logActivity({ adminType: 'main', adminName: user.name, actionType: 'toggle_sub_admin', details: { id }, ip: getIpAddress(req), userAgent: getUserAgent(req) }, tenantId);
    res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true }));
    return;
  }

  res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' }));
}

async function handleInviteLinks(req, res, tenantId) {
  const user = await validateSession(req, tenantId);
  if (!user || (!user.permissions.canCreateInvite && req.method !== 'GET')) { res.writeHead(403, corsHeaders); res.end(JSON.stringify({ error: 'Forbidden' })); return; }

  if (req.method === 'GET') {
    let query = getSupabase().from('invite_links').select('*, campaigns(name)').order('created_at', { ascending: false });
    if (tenantId) query = query.eq('tenant_id', tenantId);
    const { data: links } = await query;
    res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, inviteLinks: links || [] }));
    return;
  }

  if (req.method === 'POST') {
    const body = await readBody(req);
    const data = JSON.parse(body || '{}');
    const campaign = await getScopedCampaign(data.campaignId, tenantId);
    if (!campaign) { res.writeHead(404, corsHeaders); res.end(JSON.stringify({ error: 'Campaign not found' })); return; }
    const code = require('crypto').randomBytes(6).toString('hex');
    const insertObj = { campaign_id: data.campaignId, name: data.name, code, is_active: true, created_by_type: user.adminType, created_by_sub_admin_id: user.subAdminId };
    if (tenantId) insertObj.tenant_id = tenantId;
    const { data: created, error } = await getSupabase().from('invite_links').insert(insertObj).select().single();
    if (error) { res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: error.message })); return; }
    await logActivity({ adminType: user.adminType, subAdminId: user.subAdminId, adminName: user.name, actionType: 'create_invite', campaignId: data.campaignId, ip: getIpAddress(req), userAgent: getUserAgent(req) }, tenantId);
    res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, inviteLink: created }));
    return;
  }

  if (req.method === 'PUT') {
    const body = await readBody(req);
    const data = JSON.parse(body || '{}');
    let query = getSupabase().from('invite_links').update({ is_active: data.isActive, updated_at: new Date().toISOString() }).eq('id', data.id);
    if (tenantId) query = query.eq('tenant_id', tenantId);
    const { data: updated, error } = await query.select().single();
    if (error) { res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: error.message })); return; }
    res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, inviteLink: updated }));
    return;
  }

  res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' }));
}

async function handleAnalytics(req, res, tenantId) {
  if (req.method === 'POST') {
    try {
      const rate = checkRateLimit(`analytics:${getClientIdentifier(req)}`, 120);
      if (!rate.allowed) {
        res.writeHead(429, { ...corsHeaders, 'Retry-After': String(rate.retryAfter) });
        res.end(JSON.stringify({ error: 'Too many analytics events' }));
        return;
      }
      const body = await readBody(req, 10000);
      const data = JSON.parse(body || '{}');
      if (data.campaignId) {
        const campaign = await getScopedCampaign(data.campaignId, tenantId, true);
        if (!campaign) { res.writeHead(404, corsHeaders); res.end(JSON.stringify({ error: 'Campaign not found' })); return; }
      }
      const insertObj = {
        event_type: data.eventType || 'page_view',
        campaign_id: data.campaignId || null,
        tweet_id: data.tweetId || null,
        invite_code: data.inviteCode || null,
        visitor_id: data.visitorId || null,
        platform: data.platform || null,
        metadata: data.metadata || {}
      };
      if (tenantId) insertObj.tenant_id = tenantId;
      await getSupabase().from('analytics_events').insert(insertObj);
      res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true }));
    } catch (e) {
      res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: 'Internal error' }));
    }
    return;
  }

  const user = await validateSession(req, tenantId);
  if (!user) { res.writeHead(401, corsHeaders); res.end(JSON.stringify({ error: 'Unauthorized' })); return; }

  let query = getSupabase().from('analytics_events').select('*').order('created_at', { ascending: false }).limit(10000);
  if (tenantId) query = query.eq('tenant_id', tenantId);
  const { data: events } = await query;

  const summary = {
    totalPageViews: events?.filter(e => e.event_type === 'page_view').length || 0,
    totalCampaignViews: events?.filter(e => e.event_type === 'campaign_view').length || 0,
    totalShareClicks: events?.filter(e => e.event_type.startsWith('tweet_share')).length || 0,
    totalCopies: events?.filter(e => e.event_type === 'tweet_copy').length || 0,
    totalInviteVisits: events?.filter(e => e.event_type === 'invite_visit').length || 0,
    uniqueVisitors: new Set(events?.filter(e => e.visitor_id).map(e => e.visitor_id)).size || 0,
    sharesByPlatform: {
      x: events?.filter(e => e.event_type === 'tweet_share_x').length || 0,
      whatsapp: events?.filter(e => e.event_type === 'tweet_share_whatsapp').length || 0,
      facebook: events?.filter(e => e.event_type === 'tweet_share_facebook').length || 0,
      telegram: events?.filter(e => e.event_type === 'tweet_share_telegram').length || 0,
      native: events?.filter(e => e.event_type === 'tweet_share_native').length || 0
    },
    timeline: {}, byCampaign: {}, byInviteCode: {}
  };
  res.writeHead(200, corsHeaders); res.end(JSON.stringify({ success: true, summary }));
}

async function handleReport(req, res, tenantId) {
  if (req.method !== 'GET') { res.writeHead(405, corsHeaders); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }
  const user = await validateSession(req, tenantId);
  if (!user || user.adminType !== 'main') { res.writeHead(403, corsHeaders); res.end(JSON.stringify({ error: 'Forbidden' })); return; }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const campaignId = url.searchParams.get('campaignId');
  const format = url.searchParams.get('format') || 'html';
  if (!campaignId) { res.writeHead(400, corsHeaders); res.end(JSON.stringify({ error: 'campaignId is required' })); return; }

  let cmpQuery = getSupabase().from('campaigns').select('*').eq('id', campaignId);
  if (tenantId) cmpQuery = cmpQuery.eq('tenant_id', tenantId);
  const { data: campaign } = await cmpQuery.single();
  if (!campaign) { res.writeHead(404, corsHeaders); res.end(JSON.stringify({ error: 'Campaign not found' })); return; }

  let tweetsQuery = getSupabase().from('tweets').select('*').eq('campaign_id', campaignId).order('created_at', { ascending: true });
  if (tenantId) tweetsQuery = tweetsQuery.eq('tenant_id', tenantId);
  const { data: tweets } = await tweetsQuery;

  let eventsQuery = getSupabase().from('analytics_events').select('*').eq('campaign_id', campaignId);
  if (tenantId) eventsQuery = eventsQuery.eq('tenant_id', tenantId);
  const { data: events } = await eventsQuery;

  const campaignViews = events?.filter(e => e.event_type === 'campaign_view').length || 0;
  const uniqueVisitors = new Set(events?.filter(e => e.visitor_id).map(e => e.visitor_id)).size || 0;
  const shareClicks = events?.filter(e => e.event_type.startsWith('tweet_share')).length || 0;
  const copies = events?.filter(e => e.event_type === 'tweet_copy').length || 0;
  const mediaCount = tweets?.filter(t => t.media_url).length || 0;
  const now = new Date();

  const platformStats = { x: 0, whatsapp: 0, facebook: 0, telegram: 0, native: 0 };
  events?.forEach(e => {
    if (e.event_type === 'tweet_share_x') platformStats.x++;
    if (e.event_type === 'tweet_share_whatsapp') platformStats.whatsapp++;
    if (e.event_type === 'tweet_share_facebook') platformStats.facebook++;
    if (e.event_type === 'tweet_share_telegram') platformStats.telegram++;
    if (e.event_type === 'tweet_share_native') platformStats.native++;
  });

  const html = `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>تقرير الحملة - ${escapeHtml(campaign.name)}</title><link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;900&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Cairo',sans-serif;background:#f8fafc;color:#1e293b;line-height:1.6}.container{max-width:900px;margin:0 auto;background:#fff;min-height:100vh}.cover{background:linear-gradient(135deg,#14532d 0%,#15803d 50%,#b91c1c 100%);color:#fff;padding:60px 40px;text-align:center}.cover h1{font-size:32px;font-weight:900;margin-bottom:20px}.cover h2{font-size:22px;font-weight:700;margin-bottom:30px;opacity:.95}.content{padding:40px}.section{margin-bottom:30px;page-break-inside:avoid}.section-title{font-size:18px;font-weight:700;color:#14532d;border-right:4px solid #15803d;padding-right:12px;margin-bottom:16px}.stats-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:24px}.stat-card{background:#f0fdf4;border:1px solid #dcfce7;border-radius:12px;padding:16px;text-align:center}.stat-value{font-size:26px;font-weight:900;color:#15803d}.stat-label{font-size:12px;color:#64748b;margin-top:4px}.info-table{width:100%;border-collapse:collapse;margin-bottom:20px}.info-table th,.info-table td{padding:10px 12px;text-align:right;font-size:13px}.info-table th{background:#f0fdf4;color:#14532d;font-weight:600;border-bottom:2px solid #15803d}.info-table td{border-bottom:1px solid #e2e8f0}.footer{text-align:center;padding:20px;font-size:11px;color:#94a3b8;border-top:1px solid #e2e8f0;margin-top:40px}@media print{body{background:#fff}.container{max-width:100%}}</style></head><body><div class="container"><div class="cover"><h1>تقرير أداء الحملة الإعلامية</h1><h2>${escapeHtml(campaign.name)}</h2><div style="font-size:14px;opacity:.85;margin-top:40px"><p>تاريخ إصدار التقرير: ${formatDateAr(now)}</p></div></div><div class="content"><div class="section"><h3 class="section-title">معلومات الحملة</h3><table class="info-table"><tr><th style="width:30%">البيان</th><th>القيمة</th></tr><tr><td>اسم الحملة</td><td><strong>${escapeHtml(campaign.name)}</strong></td></tr>${campaign.description ? `<tr><td>المقدمة</td><td>${escapeHtml(campaign.description)}</td></tr>` : ''}<tr><td>تاريخ الإطلاق</td><td>${formatDateAr(campaign.target_time)}</td></tr><tr><td>الحالة</td><td>${campaign.is_active ? 'نشطة' : 'معطلة'}</td></tr></table></div><div class="section"><h3 class="section-title">الإحصائيات الرئيسية</h3><div class="stats-grid"><div class="stat-card"><div class="stat-value">${campaignViews}</div><div class="stat-label">مشاهدات الحملة</div></div><div class="stat-card"><div class="stat-value">${uniqueVisitors}</div><div class="stat-label">زوار فريدون</div></div><div class="stat-card"><div class="stat-value">${tweets?.length || 0}</div><div class="stat-label">عدد التغريدات</div></div><div class="stat-card"><div class="stat-value">${mediaCount}</div><div class="stat-label">تغريدات بوسائط</div></div><div class="stat-card"><div class="stat-value">${shareClicks}</div><div class="stat-label">ضغطات مشاركة</div></div><div class="stat-card"><div class="stat-value">${copies}</div><div class="stat-label">عمليات نسخ</div></div></div></div><div class="section"><h3 class="section-title">المشاركات حسب المنصة</h3><div class="stats-grid"><div class="stat-card"><div class="stat-value">${platformStats.x}</div><div class="stat-label">X (تويتر)</div></div><div class="stat-card"><div class="stat-value">${platformStats.whatsapp}</div><div class="stat-label">واتساب</div></div><div class="stat-card"><div class="stat-value">${platformStats.facebook}</div><div class="stat-label">فيسبوك</div></div><div class="stat-card"><div class="stat-value">${platformStats.telegram}</div><div class="stat-label">تيليجرام</div></div><div class="stat-card"><div class="stat-value">${platformStats.native}</div><div class="stat-label">مشاركة أصلية</div></div></div></div>${tweets?.length ? `<div class="section" style="page-break-before:always"><h3 class="section-title">قائمة التغريدات (${tweets.length})</h3><table class="info-table"><tr><th>#</th><th>النص</th><th>تاريخ النشر</th></tr>${tweets.map((t, i) => `<tr><td style="width:30px">${i + 1}</td><td style="max-width:400px;word-wrap:break-word">${escapeHtml(t.text || '').substring(0, 200)}</td><td style="width:140px">${formatDateAr(t.created_at)}</td></tr>`).join('')}</table></div>` : ''}<div class="footer"><p>تقرير أداء الحملة الإعلامية - ${escapeHtml(campaign.name)}</p><p>${formatDateAr(now)}</p></div></div></div></body></html>`;

  if (format === 'html' || format === 'pdf') {
    const printHtml = format === 'pdf' ? html.replace('</body>', '<script>window.onload=function(){setTimeout(function(){window.print()},500)}</script></body>') : html;
    res.writeHead(200, { ...corsHeaders, 'Content-Type': 'text/html; charset=utf-8' });
    res.end(printHtml);
  } else {
    res.writeHead(400, corsHeaders); res.end(JSON.stringify({ error: 'Unsupported format' }));
  }
}

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders); res.end(); return; }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  let path = url.pathname;
  if (path.startsWith('/api')) path = path.slice(4);
  path = path.replace(/\/+$/, '');
  if (!path) path = '/';

  try {
    if (path === '/factory' || path.startsWith('/factory/')) {
      return await factoryHandler(req, res);
    }

    const tenantContext = await resolveTenant(req);
    if (!tenantContext.tenant) {
      res.writeHead(503, corsHeaders);
      res.end(JSON.stringify({ error: 'Tenant context is not configured for this deployment' }));
      return;
    }
    const { tenantId } = tenantContext;

    if (path === '/auth' && req.method === 'POST') return await handleTenantAuth(req, res, tenantId);
    if (path === '/auth/change-password') return await handleChangePassword(req, res, tenantId);
    if (path === '/admin/identity') return await handleTenantIdentity(req, res, tenantId);
    if (path === '/logout' && req.method === 'POST') return await handleTenantLogout(req, res, tenantId);
    if (path === '/me' && req.method === 'GET') return await handleTenantMe(req, res, tenantId);
    if (path === '/config' && req.method === 'GET') return await handleConfig(req, res, tenantId);
    if (path === '/campaign') return await handleCampaign(req, res, tenantId);
    if (path === '/update') return await handleUpdate(req, res, tenantId);
    if (path === '/delete-campaign') return await handleDeleteCampaign(req, res, tenantId);
    if (path === '/delete-tweet') return await handleDeleteTweet(req, res, tenantId);
    if (path === '/sub-admins') return await handleSubAdmins(req, res, tenantId);
    if (path === '/invite-links') return await handleInviteLinks(req, res, tenantId);
    if (path === '/analytics') return await handleAnalytics(req, res, tenantId);
    if (path === '/report') return await handleReport(req, res, tenantId);

    res.writeHead(404, corsHeaders); res.end(JSON.stringify({ error: 'Endpoint not found: ' + path }));
  } catch (error) {
    console.error('API error:', error);
    res.writeHead(500, corsHeaders); res.end(JSON.stringify({ error: 'Internal server error' }));
  }
};
