const { tenantClient } = require('../lib/supabase');

function hexToRgbVariables(hex) {
  const clean = hex.replace('#', '');
  const full =
    clean.length === 3
      ? clean.split('').map((c) => c + c).join('')
      : clean;

  const r = parseInt(full.substring(0, 2), 16);
  const g = parseInt(full.substring(2, 4), 16);
  const b = parseInt(full.substring(4, 6), 16);

  return `${r} ${g} ${b}`;
}

module.exports = async (req, res) => {
  try {
    const db = tenantClient();

    const { data: settings } = await db
      .from('site_settings')
      .select('*')
      .limit(1)
      .single();

    const primary = settings?.primary_color || '#15803d';
    const secondary = settings?.secondary_color || '#d97706';
    const theme = settings?.theme_mode || 'dark';

    const css = `
:root {
  --c-primary: ${hexToRgbVariables(primary)};
  --c-secondary: ${hexToRgbVariables(secondary)};
  --c-surface: ${theme === 'light' ? '248 250 252' : '15 23 42'};
  --c-border: ${theme === 'light' ? '226 232 240' : '51 65 85'};
  --c-muted: ${theme === 'light' ? '71 85 105' : '148 163 184'};
}
`.trim();

    res.writeHead(200, {
      'Content-Type': 'text/css; charset=utf-8',
      'Cache-Control': 'public, max-age=300'
    });

    res.end(css);
  } catch (error) {
    res.writeHead(200, {
      'Content-Type': 'text/css; charset=utf-8',
      'Cache-Control': 'public, max-age=60'
    });

    res.end(`
:root {
  --c-primary: 21 128 61;
  --c-secondary: 217 119 6;
  --c-surface: 15 23 42;
  --c-border: 51 65 85;
  --c-muted: 148 163 184;
}
`.trim());
  }
};
