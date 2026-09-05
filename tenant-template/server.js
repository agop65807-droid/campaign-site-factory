// ============================================================================
// Tenant Template — Render Web Service entry point (mirrors factory/server.js).
// Serves: / -> index.html, /admin -> admin.html, /sw.js, static assets,
//         /api/health (for Render health checks), /api/* -> api/[...path].js
// Run: `npm start` (package.json) — binds $PORT on 0.0.0.0 for Render.
// ============================================================================

const http = require('http');
const fs = require('fs');
const path = require('path');

const apiRouter = require('./api/[...path].js');

const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'index.html'));
const ADMIN_HTML = fs.readFileSync(path.join(__dirname, 'admin.html'));
let SW_JS = null;
try {
  SW_JS = fs.readFileSync(path.join(__dirname, 'sw.js'));
} catch {
  SW_JS = null;
}

const HTML_HEADERS = {
  'Content-Type': 'text/html; charset=utf-8',
  'Cache-Control': 'no-cache',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload'
};

const server = http.createServer(async (req, res) => {
  const pathname = (req.url || '/').split('?')[0];

  // Health check FIRST — before static middleware (see deploy history).
  // Supports both /health (GitHub/Render convention) and /api/health.
  if (pathname === '/api/health' || pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'tenant-site', time: new Date().toISOString() }));
    return;
  }

  if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    res.writeHead(200, HTML_HEADERS);
    res.end(INDEX_HTML);
    return;
  }

  if (req.method === 'GET' && (pathname === '/admin' || pathname === '/admin.html')) {
    res.writeHead(200, HTML_HEADERS);
    res.end(ADMIN_HTML);
    return;
  }

  if (req.method === 'GET' && pathname === '/sw.js' && SW_JS) {
    res.writeHead(200, {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff'
    });
    res.end(SW_JS);
    return;
  }

  if (pathname.startsWith('/api/')) {
    try {
      await apiRouter(req, res);
    } catch (err) {
      console.error('[tenant server] Unhandled router error:', err);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
    }
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

const PORT = process.env.PORT || 3001;

async function runTenantMigrations() {
  if (!process.env.DATABASE_URL) return;
  try {
    const { Pool } = require('pg');
    const pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
      connectionTimeoutMillis: 60000
    });
    const client = await pool.connect();
    try {
      const schema = process.env.DB_SCHEMA;
      if (schema && /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(schema)) {
        await client.query(`CREATE SCHEMA IF NOT EXISTS "${schema}"`);
        await client.query(`SET search_path TO "${schema}", public`);
      }
      const files = [
        '001_base_schema.sql',
        '002_share_platforms_and_site_settings.sql',
        '003_logo_storage.sql'
      ];
      for (const f of files) {
        const sql = fs.readFileSync(path.join(__dirname, 'migrations', f), 'utf8');
        await client.query(sql);
      }
      console.log('[tenant server] Tenant migrations completed successfully');
    } finally {
      client.release();
      await pool.end();
    }
  } catch (err) {
    console.error('[tenant server] Migration warning:', err.message);
  }
}

runTenantMigrations().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Tenant template listening on port ${PORT}`);
    if (!process.env.DATABASE_URL) {
      console.warn('WARNING: DATABASE_URL is not set — API requests will fail until it is.');
    }
  });
});

module.exports = server;
