// ============================================================================
// Vercel REST API client — thin wrapper around the endpoints the provisioning
// pipeline needs. Endpoint shapes verified against current Vercel REST API
// docs (api.vercel.com) as of this build; Vercel does version its endpoints
// independently (v9/v10/v11 mixed across resources) and does change them —
// re-verify against https://vercel.com/docs/rest-api/reference before first
// live run, especially the deployments endpoint version.
//
// Auth: every call needs VERCEL_TOKEN (a personal or team access token with
// project/deployment/domain scopes). If the token belongs to a team, also
// set VERCEL_TEAM_ID — every request below appends it as ?teamId=... when
// present, per Vercel's team-scoping convention.
// ============================================================================

const VERCEL_API_BASE = 'https://api.vercel.com';

class VercelApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = 'VercelApiError';
    this.status = status;
    this.body = body;
  }
}

function buildUrl(path, teamId, extraParams = {}) {
  const url = new URL(VERCEL_API_BASE + path);
  if (teamId) url.searchParams.set('teamId', teamId);
  for (const [k, v] of Object.entries(extraParams)) {
    if (v !== undefined && v !== null) url.searchParams.set(k, v);
  }
  return url.toString();
}

async function vercelRequest(token, teamId, method, path, body, extraParams) {
  const url = buildUrl(path, teamId, extraParams);
  const res = await fetch(url, {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });

  // Basic 429 backoff — Vercel's REST API is rate-limited per-token; a single
  // retry after the suggested delay is usually enough for provisioning-scale
  // traffic (a handful of calls per tenant creation).
  if (res.status === 429) {
    const retryAfter = parseInt(res.headers.get('retry-after') || '5', 10);
    await new Promise(r => setTimeout(r, retryAfter * 1000));
    return vercelRequest(token, teamId, method, path, body, extraParams);
  }

  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON response */ }

  if (!res.ok) {
    throw new VercelApiError(
      `Vercel API ${method} ${path} failed: ${res.status} ${json?.error?.message || text}`,
      res.status,
      json
    );
  }
  return json;
}

/**
 * Creates a new Vercel project wired to the shared tenant-template git repo.
 * @param {string} token
 * @param {string|null} teamId
 * @param {{name: string, gitRepo: {type: 'github'|'gitlab'|'bitbucket', repo: string}, rootDirectory?: string, environmentVariables?: Array}} opts
 */
async function createProject(token, teamId, opts) {
  const body = {
    name: opts.name,
    framework: null,
    gitRepository: opts.gitRepo ? { type: opts.gitRepo.type, repo: opts.gitRepo.repo } : undefined,
    rootDirectory: opts.rootDirectory || null,
    environmentVariables: opts.environmentVariables || []
  };
  return vercelRequest(token, teamId, 'POST', '/v11/projects', body);
}

async function getProject(token, teamId, idOrName) {
  return vercelRequest(token, teamId, 'GET', `/v9/projects/${encodeURIComponent(idOrName)}`);
}

async function deleteProject(token, teamId, idOrName) {
  return vercelRequest(token, teamId, 'DELETE', `/v9/projects/${encodeURIComponent(idOrName)}`);
}

async function pauseProject(token, teamId, idOrName) {
  return vercelRequest(token, teamId, 'POST', `/v1/projects/${encodeURIComponent(idOrName)}/pause`);
}

async function unpauseProject(token, teamId, idOrName) {
  return vercelRequest(token, teamId, 'POST', `/v1/projects/${encodeURIComponent(idOrName)}/unpause`);
}

/**
 * Creates one or more env vars on a project in a single call.
 * @param {Array<{key: string, value: string, target: string[], type?: 'plain'|'encrypted'|'sensitive'}>} envVars
 */
async function createEnvVars(token, teamId, idOrName, envVars) {
  const payload = envVars.map(e => ({
    key: e.key,
    value: e.value,
    target: e.target || ['production', 'preview'],
    type: e.type || 'encrypted'
  }));
  return vercelRequest(token, teamId, 'POST', `/v10/projects/${encodeURIComponent(idOrName)}/env`, payload);
}

/**
 * Triggers a new deployment from the project's linked git repo (production target).
 * NOTE: verify this endpoint's current version (v13 as of this writing) against
 * https://vercel.com/docs/rest-api/reference/endpoints/deployments/create-a-new-deployment
 * before first live run — this is the Vercel resource most likely to have moved.
 */
async function createDeployment(token, teamId, opts) {
  const body = {
    name: opts.projectName,
    project: opts.projectId || opts.projectName,
    target: 'production',
    gitSource: opts.gitSource // { type: 'github', repoId, ref: 'main' } — shape depends on git provider
  };
  return vercelRequest(token, teamId, 'POST', '/v13/deployments', body, { forceNew: '1' });
}

async function getDeployment(token, teamId, deploymentId) {
  return vercelRequest(token, teamId, 'GET', `/v13/deployments/${encodeURIComponent(deploymentId)}`);
}

/** Polls a deployment until it leaves the building/queued state or times out. */
async function waitForDeploymentReady(token, teamId, deploymentId, { timeoutMs = 5 * 60 * 1000, intervalMs = 5000 } = {}) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const dep = await getDeployment(token, teamId, deploymentId);
    if (dep.readyState === 'READY') return dep;
    if (['ERROR', 'CANCELED'].includes(dep.readyState)) {
      throw new VercelApiError(`Deployment ended in state ${dep.readyState}`, 0, dep);
    }
    await new Promise(r => setTimeout(r, intervalMs));
  }
  throw new VercelApiError('Timed out waiting for deployment to become READY', 0, { deploymentId });
}

async function addDomain(token, teamId, idOrName, domainName) {
  return vercelRequest(token, teamId, 'POST', `/v10/projects/${encodeURIComponent(idOrName)}/domains`, { name: domainName });
}

async function removeDomain(token, teamId, idOrName, domainName) {
  return vercelRequest(token, teamId, 'DELETE', `/v9/projects/${encodeURIComponent(idOrName)}/domains/${encodeURIComponent(domainName)}`);
}

module.exports = {
  VercelApiError,
  createProject,
  getProject,
  deleteProject,
  pauseProject,
  unpauseProject,
  createEnvVars,
  createDeployment,
  getDeployment,
  waitForDeploymentReady,
  addDomain,
  removeDomain
};
