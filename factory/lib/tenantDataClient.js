// ============================================================================
// Talks to a TENANT's own Supabase project (its REST + Storage API, using
// that tenant's service key) — used only during provisioning, to seed the
// site_settings and main_admins rows and create the logo storage bucket.
// This is distinct from supabaseManagementClient.js, which talks to
// api.supabase.com (the control-plane API for creating/deleting projects).
// ============================================================================

async function tenantRestRequest(tenantUrl, serviceKey, method, path, body, extraHeaders = {}) {
  const res = await fetch(`${tenantUrl}/rest/v1${path}`, {
    method,
    headers: {
      'apikey': serviceKey,
      'Authorization': `Bearer ${serviceKey}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=representation',
      ...extraHeaders
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  if (!res.ok) {
    throw new Error(`Tenant REST ${method} ${path} failed: ${res.status} ${JSON.stringify(json) || text}`);
  }
  return json;
}

async function insertSiteSettings(tenantUrl, serviceKey, settings) {
  const rows = await tenantRestRequest(tenantUrl, serviceKey, 'POST', '/site_settings', {
    org_name: settings.orgName,
    site_title: settings.siteTitle || settings.orgName,
    site_description: settings.siteDescription || '',
    hashtag: settings.hashtag || '',
    logo_url: settings.logoUrl || null,
    favicon_url: settings.faviconUrl || settings.logoUrl || null,
    primary_color: settings.primaryColor,
    secondary_color: settings.secondaryColor,
    theme_mode: settings.themeMode || 'dark',
    enabled_share_platforms: settings.enabledSharePlatforms || ['x', 'whatsapp', 'facebook'],
    social_links: settings.socialLinks || {}
  });
  return rows?.[0];
}

async function insertMainAdmin(tenantUrl, serviceKey, { name, username, passwordHash, passwordSalt }) {
  const rows = await tenantRestRequest(tenantUrl, serviceKey, 'POST', '/main_admins', {
    name,
    username,
    password_hash: passwordHash,
    password_salt: passwordSalt,
    must_change_password: true
  });
  return rows?.[0];
}

/** Creates a public storage bucket for the tenant's logo/media (PRD §7b step 3). */
async function createStorageBucket(tenantUrl, serviceKey, bucketName = 'media') {
  const res = await fetch(`${tenantUrl}/storage/v1/bucket`, {
    method: 'POST',
    headers: {
      'apikey': serviceKey,
      'Authorization': `Bearer ${serviceKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ id: bucketName, name: bucketName, public: true })
  });
  if (!res.ok && res.status !== 409) { // 409 = bucket already exists, fine on retry/resume
    const text = await res.text();
    throw new Error(`Storage bucket creation failed: ${res.status} ${text}`);
  }
  return { name: bucketName };
}

/** Uploads a logo file (as a Buffer) to the media bucket and returns its public URL. */
async function uploadLogo(tenantUrl, serviceKey, bucketName, fileName, fileBuffer, contentType) {
  const res = await fetch(`${tenantUrl}/storage/v1/object/${bucketName}/${fileName}`, {
    method: 'POST',
    headers: {
      'apikey': serviceKey,
      'Authorization': `Bearer ${serviceKey}`,
      'Content-Type': contentType || 'image/png',
      'x-upsert': 'true'
    },
    body: fileBuffer
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Logo upload failed: ${res.status} ${text}`);
  }
  return `${tenantUrl}/storage/v1/object/public/${bucketName}/${fileName}`;
}

/** Basic reachability check used as the final health check in the pipeline (PRD §7b step 10). */
async function healthCheckTenantSite(siteUrl) {
  const results = { homepage: false, adminPage: false, apiConfig: false };
  try {
    const r1 = await fetch(siteUrl, { redirect: 'follow' });
    results.homepage = r1.ok;
  } catch (e) { /* leave false */ }
  try {
    const r2 = await fetch(`${siteUrl}/admin`, { redirect: 'follow' });
    results.adminPage = r2.ok;
  } catch (e) { /* leave false */ }
  try {
    const r3 = await fetch(`${siteUrl}/api/config`);
    results.apiConfig = r3.ok;
  } catch (e) { /* leave false */ }
  return results;
}

module.exports = { insertSiteSettings, insertMainAdmin, createStorageBucket, uploadLogo, healthCheckTenantSite };
