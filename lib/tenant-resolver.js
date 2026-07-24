const { tenantClient } = require('./supabase');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function normalizeSlug(value) {
  const slug = String(value || '').trim().toLowerCase();
  return /^[a-z0-9][a-z0-9-]{0,62}$/.test(slug) ? slug : null;
}

function isLocalRequest(req) {
  const host = String(req.headers.host || '').split(':')[0].toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '::1';
}

async function lookupSharedTenantBySlug(slug) {
  const db = tenantClient();
  const { data, error } = await db
    .from('tenants')
    .select('id, org_name, slug, status, supabase_project_ref')
    .eq('slug', slug)
    .eq('status', 'active')
    .maybeSingle();

  if (error) throw new Error(`Unable to resolve shared tenant: ${error.message}`);
  if (!data) throw new Error(`Configured tenant "${slug}" was not found or is inactive`);

  return {
    tenantId: data.id,
    tenant: data,
    mode: 'shared'
  };
}

async function resolveTenant(req) {
  const configuredMode = String(process.env.TENANT_DATABASE_MODE || '').trim().toLowerCase();
  const configuredId = String(process.env.TENANT_ID || '').trim();
  const configuredSlug = normalizeSlug(process.env.SITE_SLUG);

  if (configuredId) {
    if (!UUID_RE.test(configuredId)) {
      throw new Error('TENANT_ID must be a valid UUID');
    }
    return {
      tenantId: configuredId,
      tenant: { id: configuredId, slug: configuredSlug },
      mode: 'shared'
    };
  }

  if (configuredMode === 'dedicated') {
    if (!configuredSlug) throw new Error('SITE_SLUG is required for a dedicated tenant deployment');
    return {
      tenantId: null,
      tenant: { id: null, slug: configuredSlug },
      mode: 'dedicated'
    };
  }

  if (configuredSlug) {
    return lookupSharedTenantBySlug(configuredSlug);
  }

  const devTenantId = String(process.env.DEV_TENANT_ID || '').trim();
  if (process.env.NODE_ENV !== 'production' && isLocalRequest(req) && devTenantId) {
    if (!UUID_RE.test(devTenantId)) {
      throw new Error('DEV_TENANT_ID must be a valid UUID');
    }
    return {
      tenantId: devTenantId,
      tenant: { id: devTenantId, slug: null },
      mode: 'shared'
    };
  }

  return {
    tenantId: null,
    tenant: null,
    mode: 'unresolved'
  };
}

module.exports = {
  resolveTenant
};
