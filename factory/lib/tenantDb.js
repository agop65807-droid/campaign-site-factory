// ============================================================================
// Schema-per-tenant provisioning helpers. ONE Render Postgres server hosts
// the factory's own tables AND every tenant's tables — isolation between
// tenants (and between tenants and the factory) is by Postgres SCHEMA, not
// by separate database instances. Each tenant gets a "tenant_<id>" schema
// on that same shared server.
//
// Opens a short-lived Client per call (not a persistent Pool) — the factory
// process only touches a given tenant's schema during its own provisioning/
// reset operations, never on the tenant's regular request path (that's the
// tenant's own Vercel deployment, talking to the same shared server directly
// via lib/db.js + DB_SCHEMA — see that file's header comment).
// ============================================================================

const { Client } = require('pg');

async function withSharedConnection(sharedDatabaseUrl, schemaName, fn) {
  const client = new Client({
    connectionString: sharedDatabaseUrl,
    ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false }
  });
  await client.connect();
  try {
    if (schemaName) {
      await client.query(`SET search_path TO "${schemaName}", public`);
    }
    return await fn(client);
  } finally {
    await client.end();
  }
}

function schemaNameForTenant(tenantId) {
  return `tenant_${tenantId}`;
}

/** Creates the tenant's dedicated schema. Cheap and fast — no async provisioning wait needed, unlike spinning up a whole new database instance. */
async function createTenantSchema(sharedDatabaseUrl, schemaName) {
  return withSharedConnection(sharedDatabaseUrl, null, async (client) => {
    await client.query(`CREATE SCHEMA IF NOT EXISTS "${schemaName}"`);
  });
}

/** Drops the tenant's schema and everything in it — used on tenant deletion and on provisioning rollback. */
async function dropTenantSchema(sharedDatabaseUrl, schemaName) {
  return withSharedConnection(sharedDatabaseUrl, null, async (client) => {
    await client.query(`DROP SCHEMA IF EXISTS "${schemaName}" CASCADE`);
  });
}

/** Runs the bundled tenant-template migration SQL inside the tenant's own schema. */
async function runMigrations(sharedDatabaseUrl, schemaName, migrationSql) {
  return withSharedConnection(sharedDatabaseUrl, schemaName, async (client) => {
    await client.query(migrationSql);
  });
}

async function insertSiteSettings(sharedDatabaseUrl, schemaName, settings) {
  return withSharedConnection(sharedDatabaseUrl, schemaName, async (client) => {
    const { rows } = await client.query(
      `INSERT INTO site_settings
        (org_name, site_title, site_description, hashtag, logo_url, primary_color, secondary_color, theme_mode, enabled_share_platforms, social_links, logo_data_base64, logo_content_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING *`,
      [
        settings.orgName,
        settings.siteTitle || settings.orgName,
        settings.siteDescription || '',
        settings.hashtag || '',
        settings.logoDataBase64 ? '/api/logo' : (settings.logoUrl || null),
        settings.primaryColor,
        settings.secondaryColor,
        settings.themeMode || 'dark',
        JSON.stringify(settings.enabledSharePlatforms || ['x', 'whatsapp', 'facebook']),
        JSON.stringify(settings.socialLinks || {}),
        settings.logoDataBase64 || null,
        settings.logoContentType || null
      ]
    );
    return rows[0];
  });
}

/** Fetches the current site_settings row for the "edit branding" screen. Never returns the raw logo bytes — only whether one exists — to keep the response small; the logo itself previews via the tenant's own /api/logo. */
async function getSiteSettings(sharedDatabaseUrl, schemaName) {
  return withSharedConnection(sharedDatabaseUrl, schemaName, async (client) => {
    const { rows } = await client.query(
      `SELECT org_name, site_title, site_description, hashtag, logo_url, primary_color, secondary_color,
              theme_mode, enabled_share_platforms, social_links,
              (logo_data_base64 IS NOT NULL) AS has_uploaded_logo, logo_content_type
       FROM site_settings LIMIT 1`
    );
    return rows[0] || null;
  });
}

/**
 * Partial update of a tenant's branding (PRD FR4 — identity control after creation, from the
 * Factory dashboard). Only touches fields actually present in `updates`, so callers can send
 * just the fields the admin changed. A new logo upload (logoDataBase64) replaces any previous
 * one and any external logoUrl; explicitly clearing the logo (clearLogo: true) drops both.
 */
async function updateSiteSettings(sharedDatabaseUrl, schemaName, updates) {
  const hasLogoChange = updates.logoDataBase64 || updates.logoUrl !== undefined || updates.clearLogo;
  const hasFieldChange = ['orgName', 'siteTitle', 'siteDescription', 'hashtag', 'primaryColor', 'secondaryColor', 'themeMode', 'enabledSharePlatforms']
    .some(k => updates[k] !== undefined);
  if (!hasLogoChange && !hasFieldChange) return null; // nothing to update — skip opening a connection at all

  return withSharedConnection(sharedDatabaseUrl, schemaName, async (client) => {
    const setClauses = [];
    const params = [];
    const push = (col, val) => { params.push(val); setClauses.push(`${col} = $${params.length}`); };

    if (updates.orgName !== undefined) push('org_name', updates.orgName);
    if (updates.siteTitle !== undefined) push('site_title', updates.siteTitle);
    if (updates.siteDescription !== undefined) push('site_description', updates.siteDescription);
    if (updates.hashtag !== undefined) push('hashtag', updates.hashtag);
    if (updates.primaryColor !== undefined) push('primary_color', updates.primaryColor);
    if (updates.secondaryColor !== undefined) push('secondary_color', updates.secondaryColor);
    if (updates.themeMode !== undefined) push('theme_mode', updates.themeMode);
    if (updates.enabledSharePlatforms !== undefined) push('enabled_share_platforms', JSON.stringify(updates.enabledSharePlatforms));

    if (updates.logoDataBase64) {
      push('logo_data_base64', updates.logoDataBase64);
      push('logo_content_type', updates.logoContentType || 'image/png');
      push('logo_url', '/api/logo');
    } else if (updates.logoUrl !== undefined) {
      push('logo_url', updates.logoUrl);
      push('logo_data_base64', null);
      push('logo_content_type', null);
    } else if (updates.clearLogo) {
      push('logo_url', null);
      push('logo_data_base64', null);
      push('logo_content_type', null);
    }

    if (setClauses.length === 0) return null; // nothing to update

    const { rows } = await client.query(
      `UPDATE site_settings SET ${setClauses.join(', ')}, updated_at = NOW() RETURNING
        org_name, site_title, site_description, hashtag, logo_url, primary_color, secondary_color,
        theme_mode, enabled_share_platforms, (logo_data_base64 IS NOT NULL) AS has_uploaded_logo`,
      params
    );
    return rows[0];
  });
}

async function insertMainAdmin(sharedDatabaseUrl, schemaName, { name, username, passwordHash, passwordSalt }) {
  return withSharedConnection(sharedDatabaseUrl, schemaName, async (client) => {
    const { rows } = await client.query(
      `INSERT INTO main_admins (name, username, password_hash, password_salt, must_change_password)
       VALUES ($1,$2,$3,$4, true)
       RETURNING *`,
      [name, username, passwordHash, passwordSalt]
    );
    return rows[0];
  });
}

/** Used by the factory's "reset admin password" action on an existing tenant. */
async function resetMainAdminPassword(sharedDatabaseUrl, schemaName, { passwordHash, passwordSalt }) {
  return withSharedConnection(sharedDatabaseUrl, schemaName, async (client) => {
    await client.query(
      `UPDATE main_admins SET password_hash=$1, password_salt=$2, must_change_password=true WHERE is_active = true`,
      [passwordHash, passwordSalt]
    );
  });
}

/** Basic reachability check used as the final health-check step (PRD §7b step 10). */
async function healthCheckTenantSite(siteUrl) {
  const results = { homepage: false, adminPage: false, apiConfig: false };
  try { results.homepage = (await fetch(siteUrl, { redirect: 'follow' })).ok; } catch (e) { /* leave false */ }
  try { results.adminPage = (await fetch(`${siteUrl}/admin`, { redirect: 'follow' })).ok; } catch (e) { /* leave false */ }
  try { results.apiConfig = (await fetch(`${siteUrl}/api/config`)).ok; } catch (e) { /* leave false */ }
  return results;
}

module.exports = {
  schemaNameForTenant, createTenantSchema, dropTenantSchema, runMigrations,
  insertSiteSettings, getSiteSettings, updateSiteSettings,
  insertMainAdmin, resetMainAdminPassword, healthCheckTenantSite
};
