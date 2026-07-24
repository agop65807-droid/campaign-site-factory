const factoryHandler = require('./factory/[...path].js');

module.exports = async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const routedPath = String(url.searchParams.get('path') || '')
    .replace(/^\/+|\/+$/g, '');
  url.searchParams.delete('path');
  const query = url.searchParams.toString();

  req.url = `/api/factory${routedPath ? `/${routedPath}` : ''}${query ? `?${query}` : ''}`;
  return factoryHandler(req, res);
};
