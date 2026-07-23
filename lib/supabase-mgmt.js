const SUPABASE_API = 'https://api.supabase.com/v1';

function headers() {
  return {
    Authorization: `Bearer ${process.env.SUPABASE_ACCESS_TOKEN}`,
    'Content-Type': 'application/json'
  };
}

async function supabaseFetch(path, options = {}) {
  const res = await fetch(`${SUPABASE_API}${path}`, {
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
    throw new Error(`Supabase Management API error ${res.status}: ${JSON.stringify(json)}`);
  }

  return json;
}

async function createProject(slug, region = 'us-east-1') {
  return supabaseFetch('/projects', {
    method: 'POST',
    body: JSON.stringify({
      name: slug,
      organization_id: process.env.SUPABASE_ORG_ID,
      region,
      plan: 'free'
    })
  });
}

async function getProject(projectRef) {
  return supabaseFetch(`/projects/${projectRef}`, { method: 'GET' });
}

async function waitProjectHealthy(projectRef, attempts = 20) {
  for (let i = 0; i < attempts; i++) {
    const project = await getProject(projectRef);
    if (project.status === 'ACTIVE_HEALTHY') return project;
    await new Promise((r) => setTimeout(r, 5000));
  }
  throw new Error('Supabase project did not become healthy in time');
}

async function runQuery(projectRef, sql) {
  return supabaseFetch(`/projects/${projectRef}/database/query`, {
    method: 'POST',
    body: JSON.stringify({ query: sql })
  });
}

async function getApiKeys(projectRef) {
  return supabaseFetch(`/projects/${projectRef}/api-keys`, { method: 'GET' });
}

async function deleteProject(projectRef) {
  return supabaseFetch(`/projects/${projectRef}`, { method: 'DELETE' });
}

module.exports = {
  createProject,
  getProject,
  waitProjectHealthy,
  runQuery,
  getApiKeys,
  deleteProject
};
