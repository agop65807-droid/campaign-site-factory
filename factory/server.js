// ============================================================================
// Render Web Service entry point. Render runs `npm start` (see package.json),
// which runs this file — a plain Node http server that:
//   1. Serves the dashboard UI (dashboard.html) at GET /
//   2. Delegates every /api/factory/* request to the router in api/[...path].js
//
// This replaced the old Vercel-serverless deployment model for the factory.
// One genuine benefit of that move: this is now a normal long-running
// process, so there's no hard per-request execution-time limit — see the
// header comment in lib/provisioning.js for what that unblocks.
// ============================================================================

const http = require('http');
const fs = require('fs');
const path = require('path');

const apiRouter = require('./api/[...path].js');

const DASHBOARD_HTML = fs.readFileSync(path.join(__dirname, 'dashboard.html'));

const server = http.createServer(async (req, res) => {
  const pathname = (req.url || '/').split('?')[0];

  if (req.method === 'GET' && (pathname === '/' || pathname === '/dashboard.html' || pathname === '/index.html')) {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload'
    });
    res.end(DASHBOARD_HTML);
    return;
  }

  if (pathname.startsWith('/api/')) {
    try {
      await apiRouter(req, res);
    } catch (err) {
      console.error('[server] Unhandled router error:', err);
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

// Render sets PORT automatically for Web Services — must bind to it (and to
// 0.0.0.0, not localhost, so Render's proxy can reach the process).
const PORT = process.env.PORT || 3000;
async function runMigrations() {
  if (!process.env.DATABASE_URL) return;
  try {
    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false }, connectionTimeoutMillis: 60000 });
    const client = await pool.connect();
    const sql = fs.readFileSync(path.join(__dirname, 'migrations', '001_factory_schema.sql'), 'utf8');
    await client.query(sql);
    console.log('[server] Factory migrations completed successfully');
    client.release();
    await pool.end();
  } catch (err) {
    console.error('[server] Migration warning:', err.message);
  }
}

runMigrations().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Campaign Site Factory listening on port ${PORT}`);
    if (!process.env.DATABASE_URL) {
      console.warn('WARNING: DATABASE_URL is not set — API requests will fail until it is.');
    }
  });
});

module.exports = server;
