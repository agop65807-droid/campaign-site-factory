const CACHE_NAME = 'campaign-factory-v6';
const STATIC_ASSETS = ['/', '/index.html', '/admin', '/assets/app.css', '/assets/js/public.js'];

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
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
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

  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request)
        .then((response) => {
          if (!response || response.status !== 200 || response.type !== 'basic') return response;
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          return response;
        })
        .catch(() => cached);
    })
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
