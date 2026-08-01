// ═══════════════════════════════════════════════════
//  sw.js — SentinelX service worker.
//  Makes the app installable + fast on repeat loads + usable offline.
//
//  Caching policy (deliberately conservative — this is a live-data app):
//    * Cross-origin requests (ipwho.is, dns.google, Firestore, fonts, CDN…)
//      are NEVER cached. Live data must stay live.
//    * Same-origin HTML → network-first (fresh shell after a deploy),
//      cache fallback when offline.
//    * Same-origin static assets (JS/CSS/img) → cache-first, filled on first
//      fetch. The ?v= cache-busting in the HTML makes each version a distinct
//      URL, so updates land automatically without stale files.
//  Bump CACHE to force a clean refresh of cached assets.
// ═══════════════════════════════════════════════════
const CACHE = 'sentinelx-v1';
const SHELL = ['./app.html', './index.html', './css/style.css', './icon.svg', './manifest.json'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  if (new URL(req.url).origin !== location.origin) return; // let live/cross-origin hit the network

  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req)
        .then(res => { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); return res; })
        .catch(() => caches.match(req).then(r => r || caches.match('./app.html')))
    );
    return;
  }

  e.respondWith(
    caches.match(req).then(hit => hit || fetch(req).then(res => {
      if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); }
      return res;
    }))
  );
});
