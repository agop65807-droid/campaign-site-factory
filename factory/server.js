const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use('/dashboard', express.static(path.join(__dirname, 'dashboard.html')));
app.use('/lib', express.static(path.join(__dirname, 'lib')));
app.use('/tenant-migrations', express.static(path.join(__dirname, 'tenant-migrations')));
app.use('/migrations', express.static(path.join(__dirname, 'migrations')));

const handler = require('./api/[...path]');

app.all('/api/*', async (req, res) => {
  try {
    await handler(req, res);
  } catch (err) {
    console.error('Handler error:', err);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok', service: 'factory-api' }));

app.listen(PORT, () => {
  console.log(`Factory API running on port ${PORT}`);
});
