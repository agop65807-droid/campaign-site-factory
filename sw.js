const CACHE_NAME = 'campaign-factory-v7';
const STATIC_ASSETS = [
  '/campaign',
  '/campaign.html',
  '/assets/app.css',
  '/assets/js/api.js',
  '/assets/js/theme.js',
  '/assets/js/public.js'
];

async function getSiteConfig() {
  try {
    const res = await fetch('/api/config', { cache: 'no-store' });
    return await res.json();
  } catch {
    return { orgName: 'الحملة', logoUrl: '/logo-dark.png' };
  }
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) =>
      Promise.allSettled(STATIC_ASSETS.map((asset) => cache.add(asset)))
    )
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  if (event.request.url.includes('/api/')) return;
  const requestUrl = new URL(event.request.url);
  if (requestUrl.origin !== self.location.origin) return;

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (!response || response.status !== 200 || response.type !== 'basic') return response;
        const clone = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        return response;
      })
      .catch(() =>
        caches.match(event.request).then((cached) => {
          if (cached) return cached;
          if (
            event.request.mode === 'navigate' &&
            ['/campaign', '/campaign.html'].includes(requestUrl.pathname)
          ) {
            return caches.match('/campaign.html');
          }
          return Response.error();
        })
      )
  );
});

self.addEventListener('push', (event) => {
  event.waitUntil(
    getSiteConfig().then((cfg) => {
      const data = event.data ? event.data.json() : {};
      const title = data.title || cfg.orgName || 'الحملة';
      const icon = cfg.logoUrl || '/logo-dark.png';

      return self.registration.showNotification(title, {
        body: data.body || 'تحديث جديد من الحملة',
        icon,
        badge: cfg.faviconUrl || icon,
        tag: data.tag || 'campaign-notification',
        requireInteraction: data.requireInteraction || false,
        data: data.data || {}
      });
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = event.notification.data?.url || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then((list) => {
      for (const client of list) {
        if (client.url.includes(url) && 'focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});
