// ============================================================================
// Provisioning pipeline — implements PRD §7b end-to-end. Each step is
// idempotent-ish and records its own status into provisioning_jobs.steps, so
// a failed job's error is visible per-step in the dashboard, and (with the
// resume support in the API router) a job can pick back up without redoing
// completed work when re-triggered.
//
// IMPORTANT — serverless execution time: a full run (two ~1-2min cloud
// provisioning waits, a build+deploy, DNS) commonly exceeds typical
// serverless function limits. Two supported ways to run this safely:
//   1) Deploy the factory API on a Vercel plan/runtime with a long enough
//      maxDuration (Pro/Enterprise support this — see factory/vercel.json),
//      and call runProvisioningJob directly from the trigger endpoint.
//   2) (Recommended for reliability) Run one step per invocation, driven by
//      a Vercel Cron hitting /api/factory/jobs/tick every minute, which
//      calls advanceOneStep() below. This module is written so either
//      caller works — see runProvisioningJob() (full run) and
//      advanceOneStep() (single step) at the bottom.
// ============================================================================

const vercel = require('./vercelClient');
const supabaseMgmt = require('./supabaseManagementClient');
const tenantData = require('./tenantDataClient');
const vault = require('./secretsVault');
const pw = require('./passwordUtils');

const STEP_IDS = [
  'create_supabase_project',
  'run_migrations',
  'create_storage_bucket',
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

function makeStepLog(id) {
  return { step: id, status: 'pending', startedAt: null, completedAt: null, error: null };
}

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
 * Builds the ordered list of step executors. `ctx` accumulates state as
 * steps complete (supabaseRef, vercelProjectId, tenantUrl, serviceKey, ...).
 * Each executor either returns a partial ctx patch, or throws.
 */
function buildSteps({ vercelToken, vercelTeamId, supabaseOrgToken, supabaseOrgId, gitRepo, input, migrationSql }) {
  return [
    {
      id: 'create_supabase_project',
      async run(ctx) {
        const dbPassword = pw.generateStrongPassword(24);
        const project = await supabaseMgmt.createProject(supabaseOrgToken, {
          orgId: supabaseOrgId,
          name: `tenant-${input.slug}`,
          dbPassword,
          region: input.supabaseRegion || 'us-east-1'
        });
        await supabaseMgmt.waitForProjectHealthy(supabaseOrgToken, project.ref || project.id);
        return { supabaseRef: project.ref || project.id, supabaseDbPassword: dbPassword };
      },
      async rollback(ctx) {
        if (ctx.supabaseRef) await supabaseMgmt.deleteProject(supabaseOrgToken, ctx.supabaseRef).catch(() => {});
      }
    },
    {
      id: 'run_migrations',
      async run(ctx) {
        await supabaseMgmt.runSql(supabaseOrgToken, ctx.supabaseRef, migrationSql);
        const apiKeys = await supabaseMgmt.getApiKeys(supabaseOrgToken, ctx.supabaseRef);
        const conn = supabaseMgmt.extractConnectionInfo(ctx.supabaseRef, apiKeys);
        return { tenantUrl: conn.url, tenantAnonKey: conn.anonKey, tenantServiceKey: conn.serviceKey };
      }
    },
    {
      id: 'create_storage_bucket',
      async run(ctx) {
        await tenantData.createStorageBucket(ctx.tenantUrl, ctx.tenantServiceKey, 'media');
        let logoUrl = input.logoUrl || null;
        if (input.logoBase64) {
          const buf = Buffer.from(input.logoBase64, 'base64');
          logoUrl = await tenantData.uploadLogo(ctx.tenantUrl, ctx.tenantServiceKey, 'media', 'logo.png', buf, input.logoContentType);
        }
        return { logoUrl };
      }
    },
    {
      id: 'insert_site_settings',
      async run(ctx) {
        await tenantData.insertSiteSettings(ctx.tenantUrl, ctx.tenantServiceKey, {
          orgName: input.orgName,
          siteTitle: input.siteTitle || input.orgName,
          siteDescription: input.siteDescription || '',
          hashtag: input.hashtag || '',
          logoUrl: ctx.logoUrl,
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
      async run(ctx) {
        const password = pw.generateStrongPassword(16);
        const salt = pw.generateSalt();
        const passwordHash = pw.hashPassword(password, salt);
        await tenantData.insertMainAdmin(ctx.tenantUrl, ctx.tenantServiceKey, {
          name: 'المشرف الرئيسي',
          username: input.adminUsername,
          passwordHash,
          passwordSalt: salt
        });
        // One-time-visible credential — the API layer returns this to the
        // dashboard exactly once on job completion, then never again (PRD
        // §7b step 11). It is NOT stored in provisioning_jobs.input_payload.
        return { adminOneTimePassword: password };
      }
    },
    {
      id: 'create_vercel_project',
      async run(ctx) {
        const project = await vercel.createProject(vercelToken, vercelTeamId, {
          name: `tenant-${input.slug}`,
          gitRepo
        });
        return { vercelProjectId: project.id, vercelProjectName: project.name };
      },
      async rollback(ctx) {
        if (ctx.vercelProjectId) await vercel.deleteProject(vercelToken, vercelTeamId, ctx.vercelProjectId).catch(() => {});
      }
    },
    {
      id: 'set_env_vars',
      async run(ctx) {
        await vercel.createEnvVars(vercelToken, vercelTeamId, ctx.vercelProjectId, [
          { key: 'SUPABASE_URL', value: ctx.tenantUrl, target: ['production', 'preview'] },
          { key: 'SUPABASE_KEY', value: ctx.tenantServiceKey, target: ['production', 'preview'], type: 'sensitive' },
          { key: 'SUPABASE_SERVICE_ROLE_KEY', value: ctx.tenantServiceKey, target: ['production', 'preview'], type: 'sensitive' }
          // Deliberately no ADMIN_USER/ADMIN_PASS — this tenant is created with a
          // main_admins DB row from the start (security §11 item 4).
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
          gitSource: gitRepo.gitSource // { type, repoId, ref } — see README for how to obtain repoId
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
        const result = await tenantData.healthCheckTenantSite(ctx.finalUrl || ctx.vercelUrl);
        if (!result.homepage) {
          throw new Error('Health check failed: homepage did not return 200 after deployment');
        }
        return { healthCheck: result };
      }
    },
    {
      id: 'finalize',
      async run(ctx) {
        return {}; // no-op — final tenants row update happens in runProvisioningJob()
      }
    }
  ];
}

/**
 * Full synchronous run (suitable when the caller's function has a long
 * enough maxDuration — see the header comment). Rolls back all
 * already-completed steps' side effects if any step throws.
 */
async function runProvisioningJob(factoryDb, job, tenant, config) {
  const steps = buildSteps(config);
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
      supabase_project_ref: ctx.supabaseRef,
      supabase_region: config.input.supabaseRegion || 'us-east-1',
      custom_domain: config.input.subdomain ? `${config.input.subdomain}.${config.input.baseDomain}` : null,
      updated_at: nowIso()
    }).eq('id', tenant.id);

    // Store the tenant's own service key + one-time admin password, encrypted,
    // so the dashboard can display the admin password exactly once and then
    // this module never needs the plaintext again.
    if (ctx.tenantServiceKey) {
      await vault.setSecret(factoryDb, vault.KEYS.tenantSupabaseServiceKey(tenant.id), ctx.tenantServiceKey);
    }
    if (ctx.adminOneTimePassword) {
      await vault.setSecret(factoryDb, vault.KEYS.tenantMainAdminPasswordOneTime(tenant.id), ctx.adminOneTimePassword);
    }

    await updateJob(factoryDb, job.id, { status: 'succeeded', completed_at: nowIso(), current_step: null });
    return { success: true, url: ctx.finalUrl || ctx.vercelUrl, ctx };
  } catch (err) {
    // Rollback every already-completed step, in reverse order, to avoid
    // leaving orphaned Vercel/Supabase projects behind (PRD §14 risk table).
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
