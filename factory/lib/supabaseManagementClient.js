// ============================================================================
// Supabase Management API client — creates/configures/tears down a fully
// isolated Supabase project per tenant (architecture §6.3).
//
// Endpoint shapes verified against current Supabase docs (api.supabase.com)
// as of this build. Two things called out explicitly in Supabase's own docs
// that are worth re-checking before first live run:
//  1) Their key system is mid-migration: legacy anon/service_role keys are
//     being replaced by publishable (sb_publishable_...) / secret
//     (sb_secret_...) keys, deprecating the old ones by end of 2026. This
//     client tries the new /api-keys endpoint first and falls back to the
//     legacy shape returned on the project object.
//  2) The database/migrations endpoint is "select customers only" per
//     Supabase's docs — this client uses the more broadly available
//     database/query endpoint to run our migration SQL directly instead.
// ============================================================================

const SUPABASE_MGMT_BASE = 'https://api.supabase.com/v1';

class SupabaseMgmtError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = 'SupabaseMgmtError';
    this.status = status;
    this.body = body;
  }
}

async function mgmtRequest(token, method, path, body) {
  const res = await fetch(SUPABASE_MGMT_BASE + path, {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });

  if (res.status === 429) {
    const retryAfter = parseInt(res.headers.get('x-ratelimit-reset') || '5', 10);
    await new Promise(r => setTimeout(r, Math.min(retryAfter, 30) * 1000));
    return mgmtRequest(token, method, path, body);
  }

  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }

  if (!res.ok) {
    throw new SupabaseMgmtError(
      `Supabase Management API ${method} ${path} failed: ${res.status} ${json?.message || text}`,
      res.status,
      json
    );
  }
  return json;
}

/**
 * Creates a new, fully isolated Supabase project for one tenant.
 * @param {{orgId: string, name: string, dbPassword: string, region?: string}} opts
 */
async function createProject(token, opts) {
  return mgmtRequest(token, 'POST', '/projects', {
    organization_id: opts.orgId,
    name: opts.name,
    db_pass: opts.dbPassword,
    region: opts.region || 'us-east-1'
    // desired_instance_size intentionally omitted — Nano-tier scale-to-zero
    // pricing applies by default, which is the right default for a low-traffic
    // per-tenant campaign site (§14 cost risk).
  });
}

async function getProject(token, ref) {
  return mgmtRequest(token, 'GET', `/projects/${ref}`);
}

async function getProjectHealth(token, ref) {
  return mgmtRequest(token, 'GET', `/projects/${ref}/health`);
}

/** Polls project health until ACTIVE_HEALTHY or timeout. New projects take roughly 1-2 minutes to provision. */
async function waitForProjectHealthy(token, ref, { timeoutMs = 5 * 60 * 1000, intervalMs = 5000 } = {}) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const health = await getProjectHealth(token, ref);
      const services = Array.isArray(health) ? health : (health?.services || []);
      const allHealthy = services.length > 0 && services.every(s => s.status === 'ACTIVE_HEALTHY');
      if (allHealthy) return health;
    } catch (e) {
      // Health endpoint can 404/500 in the first several seconds while the project
      // is still being allocated — treat as "not ready yet" rather than a hard failure.
    }
    await new Promise(r => setTimeout(r, intervalMs));
  }
  throw new SupabaseMgmtError('Timed out waiting for Supabase project to become healthy', 0, { ref });
}

/** Runs arbitrary SQL (our migration files) against the project's database. */
async function runSql(token, ref, sql) {
  return mgmtRequest(token, 'POST', `/projects/${ref}/database/query`, { query: sql });
}

/** Fetches the project's API keys (tries the new publishable/secret system, falls back to legacy). */
async function getApiKeys(token, ref) {
  try {
    const keys = await mgmtRequest(token, 'GET', `/projects/${ref}/api-keys?reveal=true`);
    if (Array.isArray(keys) && keys.length) return keys;
  } catch (e) { /* fall through to legacy */ }
  // Legacy shape: anon/service_role keys are returned as part of the project config
  // on older projects/API versions.
  const project = await getProject(token, ref);
  return project?.api_keys || [];
}

/** Convenience: extracts { url, anonKey, serviceKey } from whichever key shape came back. */
function extractConnectionInfo(ref, apiKeys) {
  const find = (names) => {
    const match = apiKeys.find(k => names.includes(k.name) || names.includes(k.type));
    return match?.api_key || match?.value || null;
  };
  return {
    url: `https://${ref}.supabase.co`,
    anonKey: find(['anon', 'publishable']),
    serviceKey: find(['service_role', 'secret'])
  };
}

async function deleteProject(token, ref) {
  return mgmtRequest(token, 'DELETE', `/projects/${ref}`);
}

module.exports = {
  SupabaseMgmtError,
  createProject,
  getProject,
  getProjectHealth,
  waitForProjectHealthy,
  runSql,
  getApiKeys,
  extractConnectionInfo,
  deleteProject
};
