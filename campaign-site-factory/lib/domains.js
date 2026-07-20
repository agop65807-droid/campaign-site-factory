const { factoryClient } = require('./supabase');
const vercel = require('./vercel');
const { normalizeHostname } = require('./crypto');

function isValidHostname(hostname) {
  return /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(hostname);
}

function isSubdomainOfBase(hostname, baseDomain) {
  return hostname.endsWith(`.${baseDomain}`);
}

async function addTenantDomain({ tenant, hostname, setPrimary = false }) {
  const db = factoryClient();
  const cleanHostname = normalizeHostname(hostname);

  if (!isValidHostname(cleanHostname)) {
    throw new Error('Invalid hostname');
  }

  const { data: settings } = await db
    .from('factory_settings')
    .select('*')
    .limit(1)
    .single();

  const baseDomain = settings?.base_domain || 'campaigns.example.com';
  const domainType = isSubdomainOfBase(cleanHostname, baseDomain) ? 'subdomain' : 'custom';

  if (!tenant.vercel_project_id) {
    throw new Error('Tenant has no Vercel project yet');
  }

  const vercelResult = await vercel.addDomain(tenant.vercel_project_id, cleanHostname);

  const verification = {
    verification: vercelResult?.verification || [],
    nameservers: vercelResult?.nameservers || [],
    acceptedChallenges: vercelResult?.acceptedChallenges || []
  };

  const { data: existing } = await db
    .from('tenant_domains')
    .select('*')
    .eq('hostname', cleanHostname)
    .single();

  let domainRecord;

  if (existing) {
    const { data, error } = await db
      .from('tenant_domains')
      .update({
        status: 'pending_verification',
        verification,
        is_primary: setPrimary,
        updated_at: new Date().toISOString()
      })
      .eq('id', existing.id)
      .select()
      .single();

    if (error) throw error;
    domainRecord = data;
  } else {
    const { data, error } = await db
      .from('tenant_domains')
      .insert({
        tenant_id: tenant.id,
        hostname: cleanHostname,
        domain_type: domainType,
        status: 'pending_verification',
        verification,
        is_primary: setPrimary
      })
      .select()
      .single();

    if (error) throw error;
    domainRecord = data;
  }

  if (setPrimary) {
    await db
      .from('tenant_domains')
      .update({ is_primary: false, updated_at: new Date().toISOString() })
      .eq('tenant_id', tenant.id)
      .neq('id', domainRecord.id);

    await db
      .from('tenants')
      .update({
        primary_domain: cleanHostname,
        custom_domain: domainType === 'custom' ? cleanHostname : tenant.custom_domain,
        subdomain: domainType === 'subdomain' ? cleanHostname : tenant.subdomain,
        updated_at: new Date().toISOString()
      })
      .eq('id', tenant.id);
  }

  return {
    domain: domainRecord,
    dns: {
      type: domainType,
      hostname: cleanHostname,
      recommended: domainType === 'subdomain'
        ? [{ type: 'CNAME', name: cleanHostname.split('.')[0], value: 'cname.vercel-dns.com' }]
        : [
            { type: 'A', name: '@', value: '76.76.21.21' },
            { type: 'CNAME', name: 'www', value: 'cname.vercel-dns.com' }
          ]
    }
  };
}

async function removeTenantDomain({ tenant, domainId }) {
  const db = factoryClient();

  const { data: domain, error } = await db
    .from('tenant_domains')
    .select('*')
    .eq('id', domainId)
    .eq('tenant_id', tenant.id)
    .single();

  if (error || !domain) {
    throw new Error('Domain not found');
  }

  if (tenant.vercel_project_id) {
    try {
      await vercel.removeDomain(tenant.vercel_project_id, domain.hostname);
    } catch (e) {
      console.error('Vercel remove domain warning:', e.message);
    }
  }

  await db.from('tenant_domains').delete().eq('id', domain.id);

  if (tenant.primary_domain === domain.hostname) {
    const { data: nextPrimary } = await db
      .from('tenant_domains')
      .select('*')
      .eq('tenant_id', tenant.id)
      .order('created_at', { ascending: true })
      .limit(1)
      .single();

    await db
      .from('tenants')
      .update({
        primary_domain: nextPrimary?.hostname || null,
        updated_at: new Date().toISOString()
      })
      .eq('id', tenant.id);
  }

  return { success: true };
}

module.exports = {
  addTenantDomain,
  removeTenantDomain
};
