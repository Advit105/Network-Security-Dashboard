// ═══════════════════════════════════════════════════
//  threat_origins.js — Top Threat Origins breakdown
//  Replaces the world map. Same real data, higher signal:
//  ranks blocked-IP origin countries, no fake anything.
//  Reuses blocklist + geo cache (ipwho.is) the map used.
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  const GEO_CACHE_KEY = 'sentinelx_geo_cache_v2';
  const BLOCKLIST_KEY = 'sentinelx_blocklist';
  const SEV_COLOR = { danger: 'var(--red)', warn: 'var(--amber)', info: 'var(--cyan)' };

  const load = (k) => {
    try { return JSON.parse(localStorage.getItem(k)) || (k === BLOCKLIST_KEY ? [] : {}); }
    catch { return k === BLOCKLIST_KEY ? [] : {}; }
  };
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  // ISO country code → flag emoji (empty for legacy cache entries without a code)
  const flag = (code) => code && code.length === 2
    ? code.toUpperCase().replace(/./g, c => String.fromCodePoint(127397 + c.charCodeAt(0)))
    : '';

  // Geolocation is shared via window.SentinelGeo (util.js), writing the same cache key.

  const emptyState = (title, sub) =>
    `<div class="origins-empty"><div class="origins-empty-title">${title}</div><div class="origins-empty-sub">${sub}</div></div>`;

  let refreshing = false, lastKey = null;

  async function render(force) {
    const wrap = document.getElementById('threat-origins-wrap');
    if (!wrap || refreshing) return;
    const list = load(BLOCKLIST_KEY);
    const key = JSON.stringify(list.map(e => e.ip + '|' + e.severity));
    if (!force && key === lastKey) return;
    refreshing = true;

    try {
      // Geolocate any not-yet-cached IPs (gentle pacing for ipwho.is limits)
      for (const e of list) {
        if (!load(GEO_CACHE_KEY)[e.ip]) { await SentinelGeo(e.ip); await sleep(150); }
      }

      const cache = load(GEO_CACHE_KEY);
      const byCountry = {};
      let mapped = 0, unmappable = 0;
      for (const e of list) {
        const g = cache[e.ip];
        if (g && g.ok && g.country) {
          mapped++;
          const c = (byCountry[g.country] ||= { total: 0, danger: 0, warn: 0, info: 0, code: g.code || '' });
          c.total++;
          if (c[e.severity] !== undefined) c[e.severity]++;
        } else if (g && !g.ok) unmappable++;
      }

      const rows = Object.entries(byCountry).sort((a, b) => b[1].total - a[1].total);
      const max = rows.length ? rows[0][1].total : 0;

      const stat = document.getElementById('origins-stat');
      if (stat) {
        stat.textContent = list.length
          ? `${mapped} mapped · ${rows.length} countr${rows.length === 1 ? 'y' : 'ies'}` + (unmappable ? ` · ${unmappable} private` : '')
          : '';
      }

      if (!list.length) {
        wrap.innerHTML = emptyState('No threat origins yet', 'Block an IP (IP Lookup → Add to Blocklist) and its origin country appears here');
        lastKey = key; return;
      }
      if (!rows.length) {
        // Still resolving (network) — don't cache the key so it retries next cycle
        wrap.innerHTML = emptyState('Locating origins…', 'Geolocating your blocked IPs — this updates automatically');
        return;
      }

      wrap.innerHTML = rows.map(([country, c]) => {
        const dom = c.danger ? 'danger' : c.warn ? 'warn' : 'info';
        const pct = max ? Math.round(c.total / max * 100) : 0;
        const breakdown = ['danger', 'warn', 'info'].filter(s => c[s]).map(s => `${c[s]} ${s}`).join(' · ');
        const fl = flag(c.code);
        return `<div class="origin-row" title="${escHtml(country)} — ${breakdown}">
          <span class="origin-dot" style="background:${SEV_COLOR[dom]}"></span>
          <span class="origin-name">${fl ? fl + ' ' : ''}${escHtml(country)}</span>
          <span class="origin-track"><span class="origin-bar" style="width:${pct}%;background:${SEV_COLOR[dom]}"></span></span>
          <span class="origin-count">${c.total}</span>
        </div>`;
      }).join('');
      lastKey = key;
    } finally {
      refreshing = false;
    }
  }

  function start() {
    render(true);
    setInterval(() => render(false), 5000);
    window.refreshWorldMap = () => render(true); // keep the hook blocklist.js already calls
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
