const VERCEL_API = 'https://api.vercel.com';

function headers() {
  return {
    Authorization: `Bearer ${process.env.VERCEL_TOKEN}`,
    'Content-Type': 'application/json'
  };
}

function withTeam(path) {
  const teamId = process.env.VERCEL_TEAM_ID;
  if (!teamId) return path;
  return path.includes('?') ? `${path}&teamId=${teamId}` : `${path}?teamId=${teamId}`;
}

async function vercelFetch(path, options = {}) {
  const res = await fetch(`${VERCEL_API}${withTeam(path)}`, {
    ...options,
    headers: {
      ...headers(),
      ...(options.headers || {})
    }
  });

  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }

  if (!res.ok) {
    throw new Error(`Vercel API error ${res.status}: ${JSON.stringify(json)}`);
  }

  return json;
}

async function createProject(name, repo) {
  return vercelFetch('/v10/projects', {
    method: 'POST',
    body: JSON.stringify({
      name,
      framework: null,
      buildCommand: 'npm run build',
      outputDirectory: '.',
      installCommand: 'npm install',
      gitRepository: repo ? { type: 'github', repo } : undefined
    })
  });
}

async function deleteProject(projectId) {
  return vercelFetch(`/v9/projects/${projectId}`, { method: 'DELETE' });
}

async function setEnvVars(projectId, envs) {
  const results = [];
  for (const env of envs) {
    const result = await vercelFetch(`/v10/projects/${projectId}/env`, {
      method: 'POST',
      body: JSON.stringify({
        key: env.key,
        value: env.value,
        type: 'encrypted',
        target: ['production', 'preview', 'development']
      })
    });
    results.push(result);
  }
  return results;
}

async function createDeployment(projectName, repoId) {
  return vercelFetch('/v13/deployments', {
    method: 'POST',
    body: JSON.stringify({
      name: projectName,
      gitSource: repoId ? { type: 'github', ref: 'master', repoId } : undefined,
      target: 'production'
    })
  });
}

async function addDomain(projectId, hostname) {
  return vercelFetch(`/v9/projects/${projectId}/domains`, {
    method: 'POST',
    body: JSON.stringify({ name: hostname })
  });
}

async function removeDomain(projectId, hostname) {
  return vercelFetch(`/v9/projects/${projectId}/domains/${hostname}`, {
    method: 'DELETE'
  });
}

async function getDomain(projectId, hostname) {
  return vercelFetch(`/v9/projects/${projectId}/domains/${hostname}`, {
    method: 'GET'
  });
}

module.exports = {
  createProject,
  deleteProject,
  setEnvVars,
  createDeployment,
  addDomain,
  removeDomain,
  getDomain
};
