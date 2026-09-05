// ============================================================================
// Render REST API client — creates an isolated Postgres database per tenant
// (replaces supabaseManagementClient.js in the previous Supabase-based
// architecture). Endpoint shapes verified against Render's current API
// reference (api.render.com/v1) at build time — re-check against
// https://api-docs.render.com/reference before first live run, same caveat
// as the Vercel client below it in the pipeline.
//
// Auth: Bearer <Render API key> (Account Settings -> API Keys in the Render
// dashboard). ownerId is your workspace/team ID (Render dashboard URL when
// viewing your workspace, or GET /v1/owners).
//
// COST/PLAN NOTE (mirrors the PRD's original Supabase-org-limit risk, §14):
// Render's free Postgres plan allows only ONE instance at a time and expires
// after 90 days. Provisioning more than one tenant, or keeping any tenant
// long-term, requires a paid plan ('starter' or above) per database.
// ============================================================================

const RENDER_API_BASE = 'https://api.render.com/v1';

class RenderApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = 'RenderApiError';
    this.status = status;
    this.body = body;
  }
}

async function renderRequest(token, method, path, body) {
  const res = await fetch(RENDER_API_BASE + path, {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });

  if (res.status === 429) {
    const retryAfter = parseInt(res.headers.get('retry-after') || '5', 10);
    await new Promise(r => setTimeout(r, retryAfter * 1000));
    return renderRequest(token, method, path, body);
  }

  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }

  if (!res.ok) {
    throw new RenderApiError(`Render API ${method} ${path} failed: ${res.status} ${json?.message || text}`, res.status, json);
  }
  return json;
}

/**
 * Creates a new isolated Postgres instance for one tenant.
 * @param {{ownerId: string, name: string, region?: string, plan?: string, version?: string}} opts
 */
async function createDatabase(token, opts) {
  return renderRequest(token, 'POST', '/postgres', {
    name: opts.name,
    ownerId: opts.ownerId,
    plan: opts.plan || 'starter', // 'free' only allows one instance total on the account — see header note
    region: opts.region || 'oregon',
    version: opts.version || '16',
    enableHighAvailability: false
  });
}

async function getDatabase(token, postgresId) {
  return renderRequest(token, 'GET', `/postgres/${postgresId}`);
}

async function getConnectionInfo(token, postgresId) {
  return renderRequest(token, 'GET', `/postgres/${postgresId}/connection-info`);
}

/** Polls until the instance reports status 'available', or times out. New Render Postgres instances typically take 1-3 minutes. */
async function waitForDatabaseAvailable(token, postgresId, { timeoutMs = 5 * 60 * 1000, intervalMs = 5000 } = {}) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const db = await getDatabase(token, postgresId);
    if (db.status === 'available') return db;
    if (db.status === 'unhealthy' || db.status === 'suspended') {
      throw new RenderApiError(`Database ended in status ${db.status}`, 0, db);
    }
    await new Promise(r => setTimeout(r, intervalMs));
  }
  throw new RenderApiError('Timed out waiting for Postgres instance to become available', 0, { postgresId });
}

async function deleteDatabase(token, postgresId) {
  return renderRequest(token, 'DELETE', `/postgres/${postgresId}`);
}

module.exports = { RenderApiError, createDatabase, getDatabase, getConnectionInfo, waitForDatabaseAvailable, deleteDatabase };
