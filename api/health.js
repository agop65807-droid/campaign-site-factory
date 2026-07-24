const { factoryClient, tenantClient } = require('../lib/supabase');
const { resolveTenant } = require('../lib/tenant-resolver');

module.exports = async (req, res) => {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  };

  try {
    const isTenantDeployment = Boolean(
      process.env.TENANT_ID ||
      process.env.SITE_SLUG ||
      process.env.TENANT_DATABASE_MODE === 'dedicated' ||
      (process.env.NODE_ENV !== 'production' && process.env.DEV_TENANT_ID)
    );

    if (isTenantDeployment) {
      const context = await resolveTenant(req);
      if (!context.tenant) throw new Error('Tenant context is unresolved');
      let query = tenantClient().from('site_settings').select('id').limit(1);
      if (context.tenantId) query = query.eq('tenant_id', context.tenantId);
      const { error } = await query;
      if (error) throw error;
    } else {
      const { error } = await factoryClient().from('factory_settings').select('id').limit(1);
      if (error) throw error;
    }

    res.writeHead(200, headers);
    res.end(JSON.stringify({ status: 'ok', time: new Date().toISOString() }));
  } catch (error) {
    console.error('Health check failed:', error.message);
    res.writeHead(503, headers);
    res.end(JSON.stringify({ status: 'error', time: new Date().toISOString() }));
  }
};
