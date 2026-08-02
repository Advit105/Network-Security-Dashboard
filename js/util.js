// ═══════════════════════════════════════════════════
//  util.js — shared browser helpers used across modules.
//  Loaded right after toast.js (which provides window.escHtml),
//  before any feature module. Keep this dependency-free.
// ═══════════════════════════════════════════════════

// ── Geolocation (ipwho.is, cached) ────────────────────
// One implementation for every module that needs an IP's location.
// Contract: resolves to a normalized entry
//   { ok:true, lat, lon, city, country, code, isp }  on success,
//   { ok:false }                                      on a definite miss (cached),
//   { ok:false, transient:true }                      on a network error (NOT cached — retry later).
// Successes and definite misses are cached under the shared key so a known IP
// is never re-fetched; transient failures are left uncached.
window.SentinelGeo = (function () {
  const KEY = 'sentinelx_geo_cache_v2';
  const load = () => { try { return JSON.parse(localStorage.getItem(KEY)) || {}; } catch { return {}; } };

  async function geo(ip) {
    const cache = load();
    if (cache[ip]) return cache[ip];               // any cached verdict, ok or miss
    let d;
    try {
      const res = await fetch(`https://ipwho.is/${ip}`);
      if (!res.ok) return { ok: false, transient: true };
      d = await res.json();
    } catch {
      return { ok: false, transient: true };
    }
    const entry = d && d.success
      ? { ok: true, lat: d.latitude, lon: d.longitude, city: d.city || '', country: d.country || '', code: d.country_code || '', isp: d.connection?.isp || '' }
      : { ok: false };
    const c = load(); c[ip] = entry; localStorage.setItem(KEY, JSON.stringify(c));
    return entry;
  }
  geo.cached = (ip) => !!load()[ip];   // for pacing decisions (skip the sleep on a cache hit)
  geo.KEY = KEY;
  return geo;
})();

// ── File download (Blob → object URL → click) ─────────
window.SentinelDownload = function (filename, text, mime = 'text/plain') {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
};
