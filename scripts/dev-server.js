const http = require('http');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const port = Number(process.env.PORT || 3000);
const contentTypes = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8'
};

const tenantApiHandler = require('../api/[...path].js');
const factoryApiHandler = require('../api/factory/[...path].js');
const healthHandler = require('../api/health.js');
const configCssHandler = require('../api/config.css.js');
const manifestHandler = require('../api/manifest.js');

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // Handle API routes
  if (pathname === '/api/health') {
    await healthHandler(req, res);
    return;
  }

  if (pathname === '/api/config.css') {
    await configCssHandler(req, res);
    return;
  }

  if (pathname === '/api/manifest.js' || pathname === '/manifest.json') {
    await manifestHandler(req, res);
    return;
  }

  if (pathname.startsWith('/api/factory')) {
    try {
      await factoryApiHandler(req, res);
    } catch (err) {
      console.error('Dev server factory API error:', err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  if (pathname.startsWith('/api')) {
    try {
      await tenantApiHandler(req, res);
    } catch (err) {
      console.error('Dev server tenant API error:', err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // Handle static page routes
  const routes = {
    '/': 'index.html',
    '/campaign': 'campaign.html',
    '/factory': 'index.html',
    '/admin': 'admin.html'
  };
  const relativePath = routes[pathname] || pathname.replace(/^\/+/, '');
  const target = path.resolve(root, relativePath);

  if (!target.startsWith(`${root}${path.sep}`)) {
    res.writeHead(403).end('Forbidden');
    return;
  }

  fs.readFile(target, (error, file) => {
    if (error) {
      res.writeHead(error.code === 'ENOENT' ? 404 : 500).end(error.code === 'ENOENT' ? 'Not found' : 'Server error');
      return;
    }

    res.writeHead(200, {
      'Content-Type': contentTypes[path.extname(target).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-store'
    });
    res.end(file);
  });
}).listen(port, () => {
  console.log(`Full-stack development server running on http://localhost:${port}`);
});
