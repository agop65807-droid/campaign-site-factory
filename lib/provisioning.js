const fs = require('fs');
const path = require('path');
const { factoryClient, tenantClientForTenant } = require('./supabase');
const supabaseMgmt = require('./supabase-mgmt');
const vercel = require('./vercel');
const { encrypt, decrypt, pgLiteral } = require('./crypto');
const domains = require('./domains');

const PROVISION_STEPS = [
  'init',
  'create_supabase',
  'run_migration',
  'create_vercel',
  'set_env_vars',
  'deploy',
  'add_domains',
  'health_check',
  'completed'
];

async function updateJob(db, jobId, step, progress, status = 'running', errorLog = null) {
  const update = {
    step,
    progress,
    updated_at: new Date().toISOString()
  };

  if (status !== 'running') {
    update.status = status;
    update.completed_at = new Date().toISOString();
  }

  if (errorLog) {
    update.error_log = errorLog;
  }

  const { error } = await db
    .from('provisioning_jobs')
    .update(update)
    .eq('id', jobId);

  if (error) throw error;
}

async function rollback(db, tenant) {
  try {
    if (tenant.vercel_project_id && process.env.VERCEL_TOKEN) {
      await vercel.deleteProject(tenant.vercel_project_id);
    }
  } catch (e) {
    console.error('Rollback Vercel error:', e.message);
  }

  try {
    if (
      tenant.supabase_project_ref &&
      tenant.supabase_project_ref !== 'factory-shared' &&
      process.env.SUPABASE_ACCESS_TOKEN
    ) {
      await supabaseMgmt.deleteProject(tenant.supabase_project_ref);
    }
  } catch (e) {
    console.error('Rollback Supabase error:', e.message);
  }

  await db
    .from('tenants')
    .update({
      status: 'failed',
      updated_at: new Date().toISOString()
    })
    .eq('id', tenant.id);
}

async function provisionStep(tenant, jobId, input = {}) {
  const db = factoryClient();

  const { data: job } = await db
    .from('provisioning_jobs')
    .select('*')
    .eq('id', jobId)
    .single();

  if (!job) throw new Error('Job not found');

  const currentStep = job.step;

  if (currentStep === 'completed' || currentStep === 'failed') {
    return { success: true, job, done: true };
  }

  try {
    if (currentStep === 'init') {
      await updateJob(db, jobId, 'create_supabase', 10);
      return { success: true, step: 'create_supabase', progress: 10, done: false };
    }

    if (currentStep === 'create_supabase') {
      if (
        process.env.SUPABASE_ACCESS_TOKEN &&
        process.env.SUPABASE_ACCESS_TOKEN !== 'your-supabase-management-api-token' &&
        process.env.SUPABASE_ORG_ID
      ) {
        const project = await supabaseMgmt.createProject(tenant.slug, tenant.region || 'us-east-1');

        await db
          .from('tenants')
          .update({
            supabase_project_ref: project.id,
            supabase_project_url: `https://${project.id}.supabase.co`,
            updated_at: new Date().toISOString()
          })
          .eq('id', tenant.id);
      } else {
        await db
          .from('tenants')
          .update({
            supabase_project_ref: 'factory-shared',
            supabase_project_url: process.env.FACTORY_SUPABASE_URL,
            updated_at: new Date().toISOString()
          })
          .eq('id', tenant.id);
      }

      await updateJob(db, jobId, 'run_migration', 25);
      return { success: true, step: 'run_migration', progress: 25, done: false };
    }

    if (currentStep === 'run_migration') {
      const { data: freshTenant } = await db
        .from('tenants')
        .select('*')
        .eq('id', tenant.id)
        .single();

      if (freshTenant.supabase_project_ref !== 'factory-shared') {
        await supabaseMgmt.waitProjectHealthy(freshTenant.supabase_project_ref);

        const migrationSQL = fs.readFileSync(
          path.join(process.cwd(), 'sql', 'tenant', '01_migration.sql'),
          'utf8'
        );

        await supabaseMgmt.runQuery(freshTenant.supabase_project_ref, migrationSQL);

        const keys = await supabaseMgmt.getApiKeys(freshTenant.supabase_project_ref);
        const serviceKey =
          keys.find((k) => k.name === 'service_role')?.api_key ||
          keys.find((k) => k.name === 'anon')?.api_key;

        if (serviceKey) {
          await db
            .from('tenants')
            .update({
              tenant_service_key_encrypted: encrypt(serviceKey),
              updated_at: new Date().toISOString()
            })
            .eq('id', freshTenant.id);
        }

        const adminUsername = input.adminUsername || 'admin';
        const adminPassword = input.adminPassword;

        if (!adminPassword || adminPassword.length < 10) {
          throw new Error('Strong admin password is required (min 10 chars)');
        }

        const createAdminSQL = `select public.create_main_admin(${pgLiteral(adminUsername)}, ${pgLiteral(adminPassword)}, true);`;
        await supabaseMgmt.runQuery(freshTenant.supabase_project_ref, createAdminSQL);

        const identity = {
          org_name: freshTenant.org_name,
          hashtag: freshTenant.hashtag || '',
          logo_url: freshTenant.logo_url || '/logo-dark.png',
          favicon_url: freshTenant.favicon_url || '/favicon.ico',
          primary_color: freshTenant.primary_color || '#15803d',
          secondary_color: freshTenant.secondary_color || '#d97706',
          theme_mode: freshTenant.theme_mode || 'dark',
          enabled_share_platforms: freshTenant.enabled_share_platforms || ['x', 'whatsapp', 'facebook', 'telegram'],
          meta_title: freshTenant.org_name,
          meta_description: freshTenant.description || '',
          allow_admin_identity_edit: false
        };

        const identitySQL = `select public.upsert_site_settings(${pgLiteral(JSON.stringify(identity))}::jsonb);`;
        await supabaseMgmt.runQuery(freshTenant.supabase_project_ref, identitySQL);
      }

      await updateJob(db, jobId, 'create_vercel', 50);
      return { success: true, step: 'create_vercel', progress: 50, done: false };
    }

    if (currentStep === 'create_vercel') {
      const project = await vercel.createProject(tenant.slug, process.env.FACTORY_REPO || null);

      await db
        .from('tenants')
        .update({
          vercel_project_id: project.id,
          vercel_url: `https://${project.name}.vercel.app`,
          updated_at: new Date().toISOString()
        })
        .eq('id', tenant.id);

      await updateJob(db, jobId, 'set_env_vars', 70);
      return { success: true, step: 'set_env_vars', progress: 70, done: false };
    }

    if (currentStep === 'set_env_vars') {
      const { data: freshTenant } = await db
        .from('tenants')
        .select('*')
        .eq('id', tenant.id)
        .single();

      let tenantSupabaseUrl = freshTenant.supabase_project_url;
      let tenantServiceKey = '';

      if (freshTenant.tenant_service_key_encrypted) {
        tenantServiceKey = decrypt(freshTenant.tenant_service_key_encrypted);
      } else if (freshTenant.supabase_project_ref === 'factory-shared') {
        tenantServiceKey = process.env.FACTORY_SUPABASE_SERVICE_ROLE_KEY;
        tenantSupabaseUrl = process.env.FACTORY_SUPABASE_URL;
      }

      const envs = [
        { key: 'SUPABASE_URL', value: tenantSupabaseUrl },
        { key: 'SUPABASE_SERVICE_ROLE_KEY', value: tenantServiceKey },
        { key: 'SITE_SLUG', value: freshTenant.slug },
        { key: 'TENANT_DATABASE_MODE', value: freshTenant.supabase_project_ref === 'factory-shared' ? 'shared' : 'dedicated' }
      ];
      if (freshTenant.supabase_project_ref === 'factory-shared') {
        envs.push({ key: 'TENANT_ID', value: freshTenant.id });
      }

      await vercel.setEnvVars(freshTenant.vercel_project_id, envs);

      await updateJob(db, jobId, 'deploy', 85);
      return { success: true, step: 'deploy', progress: 85, done: false };
    }

    if (currentStep === 'deploy') {
      const { data: freshTenant } = await db
        .from('tenants')
        .select('*')
        .eq('id', tenant.id)
        .single();

      await vercel.createDeployment(freshTenant.slug, process.env.FACTORY_REPO_ID || null);

      await updateJob(db, jobId, 'add_domains', 92);
      return { success: true, step: 'add_domains', progress: 92, done: false };
    }

    if (currentStep === 'add_domains') {
      const { data: freshTenant } = await db
        .from('tenants')
        .select('*')
        .eq('id', tenant.id)
        .single();

      const { data: settings } = await db
        .from('factory_settings')
        .select('*')
        .limit(1)
        .single();

      const baseDomain = settings?.base_domain || 'campaigns.example.com';
      const subdomain = `${freshTenant.slug}.${baseDomain}`;

      try {
        await domains.addTenantDomain({
          tenant: freshTenant,
          hostname: subdomain,
          setPrimary: true
        });
      } catch (e) {
        console.error('Domain add warning (non-fatal):', e.message);
      }

      await updateJob(db, jobId, 'health_check', 97);
      return { success: true, step: 'health_check', progress: 97, done: false };
    }

    if (currentStep === 'health_check') {
      const { data: freshTenant } = await db
        .from('tenants')
        .select('*')
        .eq('id', tenant.id)
        .single();

      const baseUrl = freshTenant.primary_domain
        ? `https://${freshTenant.primary_domain}`
        : (freshTenant.vercel_url || `https://${freshTenant.slug}.vercel.app`);

      const checks = [
        { url: `${baseUrl}/api/health`, valid: (payload) => payload?.status === 'ok' },
        { url: `${baseUrl}/api/config`, valid: (payload) => payload?.success === true }
      ];

      for (const check of checks) {
        let timeout;
        try {
          const controller = new AbortController();
          timeout = setTimeout(() => controller.abort(), 8000);
          const res = await fetch(check.url, { signal: controller.signal });
          if (res.status !== 200) throw new Error(`Unexpected HTTP ${res.status}`);
          const payload = await res.json();
          if (!check.valid(payload)) throw new Error('Unexpected response payload');
        } catch (e) {
          throw new Error(`Health check request failed for ${check.url}: ${e.message}`);
        } finally {
          if (timeout) clearTimeout(timeout);
        }
      }

      await db
        .from('tenants')
        .update({
          status: 'active',
          updated_at: new Date().toISOString()
        })
        .eq('id', freshTenant.id);

      await updateJob(db, jobId, 'completed', 100, 'completed');
      return { success: true, step: 'completed', progress: 100, done: true };
    }

    throw new Error(`Unknown step: ${currentStep}`);
  } catch (error) {
    await updateJob(db, jobId, currentStep, 0, 'failed', error.message);

    const { data: freshTenant } = await db
      .from('tenants')
      .select('*')
      .eq('id', tenant.id)
      .single();

    await rollback(db, freshTenant);

    return {
      success: false,
      error: error.message,
      done: true
    };
  }
}

module.exports = {
  PROVISION_STEPS,
  provisionStep
};
