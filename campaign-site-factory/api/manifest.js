const { tenantClient } = require('../lib/supabase');

module.exports = async (req, res) => {
  let cfg = {};
  try {
    const { data } = await tenantClient()
      .from('site_settings')
      .select('*')
      .limit(1)
      .single();
    cfg = data || {};
  } catch (e) {}

  const manifest = {
    name: cfg.org_name || 'الحملة',
    short_name: (cfg.org_name || 'الحملة').substring(0, 12),
    description: cfg.meta_description || 'منصة حملة إلكترونية موحدة',
    dir: 'rtl',
    lang: 'ar',
    start_url: '/',
    display: 'standalone',
    background_color: cfg.theme_mode === 'light' ? '#f1f5f9' : '#0f172a',
    theme_color: cfg.primary_color || '#15803d',
    icons: [
      { src: cfg.logo_url || '/logo-dark.png', sizes: '192x192', type: 'image/png' },
      { src: cfg.logo_url || '/logo-dark.png', sizes: '512x512', type: 'image/png' }
    ]
  };

  res.writeHead(200, {
    'Content-Type': 'application/manifest+json; charset=utf-8',
    'Cache-Control': 'public, max-age=300'
  });
  res.end(JSON.stringify(manifest));
};
