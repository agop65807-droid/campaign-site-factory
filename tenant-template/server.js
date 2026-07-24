const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.json({ limit: '500kb' }));
app.use(express.urlencoded({ extended: true }));

app.use('/lib', express.static(path.join(__dirname, 'lib')));
app.use('/migrations', express.static(path.join(__dirname, 'migrations')));

const handler = require('./api/[...path]');

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

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

app.get('/health', (req, res) => res.json({ status: 'ok', service: 'tenant-site' }));

app.use(express.static(path.join(__dirname), {
  index: 'index.html',
  extensions: ['html'],
  dotfiles: 'ignore'
}));

app.listen(PORT, () => {
  console.log(`Tenant site running on port ${PORT}`);
});
