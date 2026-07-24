const CACHE_NAME = 'campaign-system-v4';
const STATIC_ASSETS = [
  '/',
  '/admin',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
    })
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
          if (!response || response.status !== 200 || response.type !== 'basic') {
            return response;
          }
          const responseToCache = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
          return response;
        })
        .catch(() => cached);
    })
  );
});

// Fallback identity, mirrors DEFAULT_SITE_CONFIG in api/[...path].js — used whenever
// /api/config is unreachable or a site_settings row doesn't exist yet, so behavior is
// unchanged until a tenant's identity is actually configured (Phase 2 foundation, §6.2).
const FALLBACK_ORG_NAME = 'لجنة اعتصام أبناء المهرة';
const FALLBACK_ICON = '/logo-dark.png';

async function getSiteIdentity() {
  try {
    const res = await fetch('/api/config');
    const data = await res.json();
    if (data && data.success && data.config) {
      return {
        orgName: data.config.orgName || FALLBACK_ORG_NAME,
        icon: data.config.logoUrl || FALLBACK_ICON
      };
    }
  } catch (e) { /* fall through to defaults */ }
  return { orgName: FALLBACK_ORG_NAME, icon: FALLBACK_ICON };
}

self.addEventListener('push', (event) => {
  const data = event.data ? event.data.json() : {};
  event.waitUntil(
    getSiteIdentity().then((identity) => {
      const title = data.title || identity.orgName;
      const options = {
        body: data.body || 'تحديث جديد',
        icon: identity.icon,
        badge: identity.icon,
        tag: data.tag || 'campaign-notification',
        requireInteraction: data.requireInteraction || false,
        data: data.data || {}
      };
      return self.registration.showNotification(title, options);
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = event.notification.data?.url || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then((windowClients) => {
      for (let client of windowClients) {
        if (client.url === url && 'focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});
