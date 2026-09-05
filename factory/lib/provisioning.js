// ============================================================================
// Provisioning pipeline — implements PRD §7b end-to-end on the final chosen
// architecture: ONE shared Render Postgres server hosts the factory's own
// tables AND every tenant's tables (isolated by Postgres schema, one
// "tenant_<id>" schema per tenant) — not a separate database instance per
// tenant. Tenant frontend + API still deploy to Vercel, same as before.
//
// WHY SCHEMA-PER-TENANT ON ONE SERVER INSTEAD OF ONE INSTANCE PER TENANT:
// this was an explicit later decision — one Render Postgres resource total,
// simpler to operate and far cheaper than paying for N separate instances.
// Isolation is still real (each tenant's tables live only in its own
// schema, unreachable through normal application code without deliberately
// changing search_path), just not as strong as fully separate database
// processes — an acceptable tradeoff for this internal tool. See the
// project README for the one operational consequence worth knowing:
// Postgres's max_connections is now shared across the factory AND every
// tenant's Vercel deployment, not partitioned per tenant.
//
// EXECUTION MODEL: this factory runs as a persistent Node process on Render
// (see server.js), not a Vercel serverless function, so there's no hard
// execution-time limit forcing a cron-tick workaround — runProvisioningJob()
// just runs the whole pipeline in one long-lived async call, fired in the
// background by the API route that creates the job.
// ============================================================================

const vercel = require('./vercelClient');
const tenantDb = require('./tenantDb');
const vault = require('./secretsVault');
const pw = require('./passwordUtils');

const STEP_IDS = [
  'create_tenant_schema',
  'run_migrations',
  'insert_site_settings',
  'create_main_admin',
  'create_vercel_project',
  'set_env_vars',
  'deploy',
  'add_domain',
  'health_check',
  'finalize'
];

function nowIso() { return new Date().toISOString(); }
function makeStepLog(id) { return { step: id, status: 'pending', startedAt: null, completedAt: null, error: null }; }

async function updateJob(factoryDb, jobId, patch) {
  await factoryDb.from('provisioning_jobs').update({ ...patch }).eq('id', jobId);
}

async function appendStepLog(factoryDb, job, stepId, patchFn) {
  const steps = job.steps && job.steps.length ? job.steps : STEP_IDS.map(makeStepLog);
  const idx = steps.findIndex(s => s.step === stepId);
  if (idx === -1) steps.push(patchFn(makeStepLog(stepId)));
  else steps[idx] = patchFn(steps[idx]);
  await updateJob(factoryDb, job.id, { steps, current_step: stepId });
  job.steps = steps;
  return steps;
}

/**
 * Builds the ordered list of step executors. `ctx` accumulates state
 * (schemaName, vercelProjectId, finalUrl, ...) as steps complete.
 */
function buildSteps({ sharedDatabaseUrl, vercelToken, vercelTeamId, gitRepo, input, migrationSql, tenantId }) {
  const schemaName = tenantDb.schemaNameForTenant(tenantId);

  return [
    {
      id: 'create_tenant_schema',
      async run() {
        await tenantDb.createTenantSchema(sharedDatabaseUrl, schemaName);
        return { schemaName };
      },
      async rollback() {
        await tenantDb.dropTenantSchema(sharedDatabaseUrl, schemaName).catch(() => {});
      }
    },
    {
      id: 'run_migrations',
      async run() {
        await tenantDb.runMigrations(sharedDatabaseUrl, schemaName, migrationSql);
        return {};
      }
    },
    {
      id: 'insert_site_settings',
      async run() {
        await tenantDb.insertSiteSettings(sharedDatabaseUrl, schemaName, {
          orgName: input.orgName,
          siteTitle: input.siteTitle || input.orgName,
          siteDescription: input.siteDescription || '',
          hashtag: input.hashtag || '',
          logoUrl: input.logoUrl || null,
          logoDataBase64: input.logoBase64 || null,
          logoContentType: input.logoContentType || null,
          primaryColor: input.primaryColor,
          secondaryColor: input.secondaryColor,
          themeMode: input.themeMode || 'dark',
          enabledSharePlatforms: input.enabledSharePlatforms || ['x', 'whatsapp', 'facebook']
        });
        return {};
      }
    },
    {
      id: 'create_main_admin',
      async run() {
        const password = pw.generateStrongPassword(16);
        const salt = pw.generateSalt();
        const passwordHash = pw.hashPassword(password, salt);
        await tenantDb.insertMainAdmin(sharedDatabaseUrl, schemaName, {
          name: 'المشرف الرئيسي',
          username: input.adminUsername,
          passwordHash,
          passwordSalt: salt
        });
        // One-time-visible credential — returned to the dashboard exactly
        // once on job completion, then never again (PRD §7b step 11).
        return { adminOneTimePassword: password };
      }
    },
    {
      id: 'create_vercel_project',
      async run(ctx) {
        const project = await vercel.createProject(vercelToken, vercelTeamId, { name: `tenant-${input.slug}`, gitRepo });
        return { vercelProjectId: project.id, vercelProjectName: project.name };
      },
      async rollback(ctx) {
        if (ctx.vercelProjectId) await vercel.deleteProject(vercelToken, vercelTeamId, ctx.vercelProjectId).catch(() => {});
      }
    },
    {
      id: 'set_env_vars',
      async run(ctx) {
        // Every tenant gets the SAME DATABASE_URL (one shared server) — what
        // isolates this tenant is DB_SCHEMA, read by lib/db.js
        // to SET search_path on every connection (see that file's header).
        await vercel.createEnvVars(vercelToken, vercelTeamId, ctx.vercelProjectId, [
          { key: 'DATABASE_URL', value: sharedDatabaseUrl, target: ['production', 'preview'], type: 'sensitive' },
          { key: 'DB_SCHEMA', value: schemaName, target: ['production', 'preview'] }
        ]);
        return {};
      }
    },
    {
      id: 'deploy',
      async run(ctx) {
        const deployment = await vercel.createDeployment(vercelToken, vercelTeamId, {
          projectName: ctx.vercelProjectName,
          projectId: ctx.vercelProjectId,
          gitSource: gitRepo.gitSource
        });
        const ready = await vercel.waitForDeploymentReady(vercelToken, vercelTeamId, deployment.id || deployment.uid);
        return { deploymentId: deployment.id || deployment.uid, vercelUrl: `https://${ready.url}` };
      }
    },
    {
      id: 'add_domain',
      async run(ctx) {
        if (!input.subdomain) return { finalUrl: ctx.vercelUrl };
        const domain = `${input.subdomain}.${input.baseDomain}`;
        await vercel.addDomain(vercelToken, vercelTeamId, ctx.vercelProjectId, domain);
        return { finalUrl: `https://${domain}` };
      }
    },
    {
      id: 'health_check',
      async run(ctx) {
        const result = await tenantDb.healthCheckTenantSite(ctx.finalUrl || ctx.vercelUrl);
        if (!result.homepage) throw new Error('Health check failed: homepage did not return 200 after deployment');
        return { healthCheck: result };
      }
    },
    { id: 'finalize', async run() { return {}; } }
  ];
}

async function runProvisioningJob(factoryDb, job, tenant, config) {
  const steps = buildSteps({ ...config, tenantId: tenant.id });
  let ctx = {};
  const completedSteps = [];

  await updateJob(factoryDb, job.id, { status: 'running', started_at: nowIso() });
  await factoryDb.from('tenants').update({ status: 'provisioning' }).eq('id', tenant.id);

  try {
    for (const step of steps) {
      await appendStepLog(factoryDb, job, step.id, s => ({ ...s, status: 'running', startedAt: nowIso() }));
      try {
        const patch = await step.run(ctx);
        ctx = { ...ctx, ...patch };
        completedSteps.push(step);
        await appendStepLog(factoryDb, job, step.id, s => ({ ...s, status: 'succeeded', completedAt: nowIso() }));
      } catch (stepErr) {
        await appendStepLog(factoryDb, job, step.id, s => ({ ...s, status: 'failed', completedAt: nowIso(), error: stepErr.message }));
        throw stepErr;
      }
    }

    await factoryDb.from('tenants').update({
      status: 'active',
      vercel_project_id: ctx.vercelProjectId,
      vercel_project_name: ctx.vercelProjectName,
      vercel_url: ctx.finalUrl || ctx.vercelUrl,
      schema_name: ctx.schemaName,
      custom_domain: config.input.subdomain ? `${config.input.subdomain}.${config.input.baseDomain}` : null,
      updated_at: nowIso()
    }).eq('id', tenant.id);

    // The one-time admin password, encrypted, so the dashboard can display
    // it exactly once ("reveal password"). No per-tenant DB connection
    // secret needed anymore — every tenant shares the same DATABASE_URL,
    // and its schema_name is stored plainly on the tenants row above.
    if (ctx.adminOneTimePassword) {
      await vault.setSecret(factoryDb, vault.KEYS.tenantMainAdminPasswordOneTime(tenant.id), ctx.adminOneTimePassword);
    }

    await updateJob(factoryDb, job.id, { status: 'succeeded', completed_at: nowIso(), current_step: null });
    return { success: true, url: ctx.finalUrl || ctx.vercelUrl, ctx };
  } catch (err) {
    // Rollback every already-completed step, in reverse order, to avoid
    // leaving orphaned Vercel projects or tenant schemas behind (PRD §14).
    for (const step of [...completedSteps].reverse()) {
      if (typeof step.rollback === 'function') {
        try { await step.rollback(ctx); } catch (rbErr) { /* best-effort */ }
      }
    }
    await updateJob(factoryDb, job.id, { status: 'failed', error_message: err.message, completed_at: nowIso() });
    await factoryDb.from('tenants').update({ status: 'failed', updated_at: nowIso() }).eq('id', tenant.id);
    return { success: false, error: err.message };
  }
}

module.exports = { STEP_IDS, buildSteps, runProvisioningJob };
