/* Dynamic identity loader — applies tenant branding from /api/config */
(async function applyTheme() {
  try {
    const res = await fetch('/api/config');
    const cfg = await res.json();

    document.title = cfg.metaTitle || cfg.orgName || document.title;
    const md = document.querySelector('meta[name="description"]');
    if (md && cfg.metaDescription) md.setAttribute('content', cfg.metaDescription);

    if (cfg.themeMode === 'light') document.body.classList.add('theme-light');
    else document.body.classList.remove('theme-light');

    if (cfg.faviconUrl) {
      let f = document.querySelector('link[rel="icon"]');
      if (!f) { f = document.createElement('link'); f.rel = 'icon'; document.head.appendChild(f); }
      f.href = cfg.faviconUrl;
    }

    window.__SITE_CONFIG__ = cfg;
    document.dispatchEvent(new CustomEvent('site:ready', { detail: cfg }));
  } catch (e) {
    window.__SITE_CONFIG__ = {};
    document.dispatchEvent(new CustomEvent('site:ready', { detail: {} }));
  }
})();
