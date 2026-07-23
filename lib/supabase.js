const { createClient } = require('@supabase/supabase-js');
const { decrypt } = require('./crypto');

function factoryClient() {
  return createClient(
    process.env.FACTORY_SUPABASE_URL,
    process.env.FACTORY_SUPABASE_SERVICE_ROLE_KEY,
    { auth: { persistSession: false } }
  );
}

function tenantClient() {
  return createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY,
    { auth: { persistSession: false } }
  );
}

function tenantClientForTenant(tenant) {
  if (tenant?.tenant_service_key_encrypted) {
    const serviceKey = decrypt(tenant.tenant_service_key_encrypted);
    return createClient(tenant.supabase_project_url, serviceKey, {
      auth: { persistSession: false }
    });
  }
  return tenantClient();
}

module.exports = {
  factoryClient,
  tenantClient,
  tenantClientForTenant
};
