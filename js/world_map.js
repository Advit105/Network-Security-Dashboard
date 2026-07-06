// ═══════════════════════════════════════════════════
//  world_map.js — Threat Origin Map (real data only)
//  Base map: Natural Earth 50m countries TopoJSON
//  Markers:  user's blocklist, geolocated via ip-api.com
//            + user's own location (green "YOU" node)
//  Arcs:     blocked-IP origin → user's location
//  No simulated cities, no random attacks.
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  // ── Cropped equirectangular projection ────────────
  // Trim Antarctica + empty polar ocean so continents fill the frame.
  const LON_MIN = -180, LON_MAX = 180;
  const LAT_MAX = 82, LAT_MIN = -56;
  const W = 1000;
  const H = Math.round(W * (LAT_MAX - LAT_MIN) / (LON_MAX - LON_MIN)); // keeps degrees square
  const NS = 'http://www.w3.org/2000/svg';
  const GEO_CACHE_KEY = 'sentinelx_geo_cache_v2';
  const BLOCKLIST_KEY = 'sentinelx_blocklist';

  function px(lon) { return ((lon - LON_MIN) / (LON_MAX - LON_MIN)) * W; }
  function py(lat) { return ((LAT_MAX - lat) / (LAT_MAX - LAT_MIN)) * H; }

  // ── GeoJSON geometry → SVG path "d" string ────────
  function geoToSVGPath(geometry) {
    let d = '';

    function projectRing(ring, close) {
      let s = '';
      for (let i = 0; i < ring.length; i++) {
        const x = px(ring[i][0]).toFixed(1);
        const y = py(ring[i][1]).toFixed(1);
        s += (i === 0 ? 'M' : 'L') + x + ',' + y;
      }
      return close ? s + 'Z' : s;
    }

    if (geometry.type === 'Polygon') {
      geometry.coordinates.forEach(ring => { d += projectRing(ring, true); });
    } else if (geometry.type === 'MultiPolygon') {
      geometry.coordinates.forEach(polygon => {
        polygon.forEach(ring => { d += projectRing(ring, true); });
      });
    } else if (geometry.type === 'LineString') {
      d += projectRing(geometry.coordinates, false);
    } else if (geometry.type === 'MultiLineString') {
      geometry.coordinates.forEach(line => { d += projectRing(line, false); });
    }
    return d;
  }

  // ── Severity → color mapping (matches blocklist) ──
  const SEV_COLOR = { danger: '#fa4d56', warn: '#f1c21b', info: '#4589ff', home: '#42be65' };
  const SEV_GLOW  = { danger: 'rgba(250,77,86,0.18)', warn: 'rgba(241,194,27,0.18)', info: 'rgba(69,137,255,0.15)', home: 'rgba(66,190,101,0.18)' };

  // ── State ─────────────────────────────────────────
  let svg = null, markerG = null, arcG = null;
  let statusEl = null, emptyEl = null;
  let homeLoc = null;        // { lat, lon, city, country, ip }
  let lastRenderKey = null;
  let refreshing = false;

  // ── Storage helpers ───────────────────────────────
  function loadBlocklistSafe() {
    try { return JSON.parse(localStorage.getItem(BLOCKLIST_KEY)) || []; } catch { return []; }
  }
  function loadGeoCache() {
    try { return JSON.parse(localStorage.getItem(GEO_CACHE_KEY)) || {}; } catch { return {}; }
  }
  function cacheGeo(ip, entry) {
    const c = loadGeoCache();
    c[ip] = entry;
    localStorage.setItem(GEO_CACHE_KEY, JSON.stringify(c));
  }

  const sleep = ms => new Promise(r => setTimeout(r, ms));

  // ── Geolocate one IP via ipwho.is (cached) ────────
  // Free, keyless, HTTPS + CORS. Failed lookups (private ranges etc.)
  // are cached too — they never succeed. Network errors are NOT cached
  // so they retry next cycle.
  async function geolocate(ip) {
    const cached = loadGeoCache()[ip];
    if (cached) return cached;
    try {
      const res = await fetch(`https://ipwho.is/${ip}`);
      if (!res.ok) return { ok: false, reason: 'http ' + res.status, transient: true };
      const d = await res.json();
      const entry = d.success
        ? { ok: true, lat: d.latitude, lon: d.longitude, city: d.city || '', country: d.country || '' }
        : { ok: false, reason: d.message || 'lookup failed' };
      cacheGeo(ip, entry);
      return entry;
    } catch {
      return { ok: false, reason: 'network', transient: true };
    }
  }

  // Own location — fetched fresh each page load (IP can change between sessions)
  async function locateSelf() {
    try {
      const res = await fetch('https://ipwho.is/');
      const d = await res.json();
      if (d.success) return { lat: d.latitude, lon: d.longitude, city: d.city || '', country: d.country || '', ip: d.ip };
    } catch { /* offline — map still renders, just without the home node */ }
    return null;
  }

  // ── SVG marker builders ───────────────────────────
  function clearLayer(g) { while (g.firstChild) g.removeChild(g.firstChild); }

  function buildMarker(x, y, sev, label, tooltip, opts = {}) {
    const color = SEV_COLOR[sev] || SEV_COLOR.info;
    const g = document.createElementNS(NS, 'g');
    g.setAttribute('class', 'map-marker' + (opts.alwaysLabel ? ' map-marker-home' : ''));

    const title = document.createElementNS(NS, 'title');
    title.textContent = tooltip;
    g.appendChild(title);

    // Threat markers pivot into the IP Lookup tool on click.
    if (opts.ip) {
      g.addEventListener('click', () => {
        if (typeof navigateTo !== 'function') return;
        navigateTo('ips');
        const inp = document.getElementById('ip-input');
        if (inp) { inp.value = opts.ip; document.getElementById('lookup-btn')?.click(); }
      });
    }

    // Expanding pulse ring
    const ring = document.createElementNS(NS, 'circle');
    ring.setAttribute('cx', x.toFixed(1)); ring.setAttribute('cy', y.toFixed(1));
    ring.setAttribute('r', '3');
    ring.setAttribute('fill', 'none');
    ring.setAttribute('stroke', color);
    ring.setAttribute('stroke-width', '1');
    ring.setAttribute('opacity', '0.55');
    const animR = document.createElementNS(NS, 'animate');
    animR.setAttribute('attributeName', 'r');
    animR.setAttribute('values', '2.5;11');
    animR.setAttribute('dur', '2.4s');
    animR.setAttribute('repeatCount', 'indefinite');
    ring.appendChild(animR);
    const animO = document.createElementNS(NS, 'animate');
    animO.setAttribute('attributeName', 'opacity');
    animO.setAttribute('values', '0.55;0');
    animO.setAttribute('dur', '2.4s');
    animO.setAttribute('repeatCount', 'indefinite');
    ring.appendChild(animO);
    g.appendChild(ring);

    // Soft glow
    const glow = document.createElementNS(NS, 'circle');
    glow.setAttribute('cx', x.toFixed(1)); glow.setAttribute('cy', y.toFixed(1));
    glow.setAttribute('r', '6.5');
    glow.setAttribute('fill', SEV_GLOW[sev] || SEV_GLOW.info);
    glow.setAttribute('filter', 'url(#glow-city)');
    g.appendChild(glow);

    // Outer halo ring (crisp)
    const halo = document.createElementNS(NS, 'circle');
    halo.setAttribute('cx', x.toFixed(1)); halo.setAttribute('cy', y.toFixed(1));
    halo.setAttribute('r', '3.4');
    halo.setAttribute('fill', 'none');
    halo.setAttribute('stroke', color);
    halo.setAttribute('stroke-width', '0.9');
    halo.setAttribute('opacity', '0.55');
    g.appendChild(halo);

    // Core dot (white center for a crisp beacon look)
    const dot = document.createElementNS(NS, 'circle');
    dot.setAttribute('cx', x.toFixed(1)); dot.setAttribute('cy', y.toFixed(1));
    dot.setAttribute('r', '1.9');
    dot.setAttribute('fill', color);
    g.appendChild(dot);

    // Label — hidden by default, shown on hover (prevents overlap clutter).
    // The home ("YOU") node is always labelled.
    if (label) {
      const padX = 3.2, fh = 7;
      const wApprox = label.length * 4.0 + padX * 2;
      const lg = document.createElementNS(NS, 'g');
      lg.setAttribute('class', opts.alwaysLabel ? 'mlabel mlabel-on' : 'mlabel');
      lg.setAttribute('transform', `translate(${x.toFixed(1)}, ${(y - 7).toFixed(1)})`);

      const bg = document.createElementNS(NS, 'rect');
      bg.setAttribute('x', (-wApprox / 2).toFixed(1));
      bg.setAttribute('y', (-fh - 2).toFixed(1));
      bg.setAttribute('width', wApprox.toFixed(1));
      bg.setAttribute('height', (fh + 4).toFixed(1));
      bg.setAttribute('rx', '2');
      bg.setAttribute('fill', 'rgba(11,14,20,0.82)');
      bg.setAttribute('stroke', color);
      bg.setAttribute('stroke-width', '0.4');
      bg.setAttribute('stroke-opacity', '0.5');
      lg.appendChild(bg);

      const txt = document.createElementNS(NS, 'text');
      txt.setAttribute('x', '0'); txt.setAttribute('y', '-1.5');
      txt.setAttribute('text-anchor', 'middle');
      txt.setAttribute('fill', color);
      txt.setAttribute('font-size', '5.6');
      txt.setAttribute('font-family', 'JetBrains Mono, monospace');
      txt.setAttribute('font-weight', '700');
      txt.setAttribute('letter-spacing', '0.4');
      txt.textContent = label;
      lg.appendChild(txt);
      g.appendChild(lg);
    }
    return g;
  }

  function buildArc(a, b, color, delay) {
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2 - Math.abs(a.x - b.x) * 0.15 - 20;
    const p = document.createElementNS(NS, 'path');
    p.setAttribute('d', `M${a.x.toFixed(1)},${a.y.toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}`);
    p.setAttribute('stroke', color);
    p.setAttribute('stroke-width', '0.8');
    p.setAttribute('fill', 'none');
    p.setAttribute('filter', 'url(#glow-arc)');
    p.classList.add('atk-line');
    p.style.animationDelay = delay + 's';
    return p;
  }

  // ── Status line + empty state (honest counts) ─────
  function updateStatus(total, mapped, unmapped) {
    const headerStats = document.getElementById('map-stats');
    if (emptyEl) emptyEl.style.display = total === 0 ? 'flex' : 'none';
    if (statusEl) {
      if (total === 0) { statusEl.style.display = 'none'; }
      else {
        statusEl.style.display = 'inline-flex';
        let txt = `${mapped} of ${total} blocked IP${total === 1 ? '' : 's'} mapped`;
        if (unmapped > 0) txt += ` · ${unmapped} private/unmappable`;
        statusEl.textContent = txt;
      }
    }
    if (headerStats) {
      headerStats.textContent = homeLoc
        ? `origin: ${homeLoc.city || homeLoc.ip}`
        : 'origin: offline';
    }
  }

  // ── Re-render markers + arcs from live data ───────
  async function updateMarkers(force) {
    if (!svg || refreshing) return;
    const list = loadBlocklistSafe();
    const renderKey = JSON.stringify(list.map(e => e.ip + '|' + e.severity)) + '@' + (homeLoc ? homeLoc.ip : '');
    if (!force && renderKey === lastRenderKey) return;
    refreshing = true;

    try {
      const located = [];
      let unmapped = 0;
      for (const e of list) {
        const wasCached = !!loadGeoCache()[e.ip];
        const geo = await geolocate(e.ip);
        if (geo.ok) located.push({ ...e, ...geo });
        else if (!geo.transient) unmapped++;
        if (!wasCached) await sleep(150); // stay well under ip-api's 45 req/min
      }

      clearLayer(arcG);
      clearLayer(markerG);

      const home = homeLoc ? { x: px(homeLoc.lon), y: py(homeLoc.lat) } : null;

      located.forEach((m, i) => {
        const pt = { x: px(m.lon), y: py(m.lat) };
        if (home) arcG.appendChild(buildArc(pt, home, SEV_COLOR[m.severity] || SEV_COLOR.info, -(i * 0.45)));
        const label = (m.city || m.ip).toUpperCase().slice(0, 14);
        const tooltip = `${m.ip} — ${[m.city, m.country].filter(Boolean).join(', ')}\n${m.reason}\nClick to investigate in IP Lookup`;
        markerG.appendChild(buildMarker(pt.x, pt.y, m.severity, label, tooltip, { ip: m.ip }));
      });

      if (home) {
        markerG.appendChild(buildMarker(
          home.x, home.y, 'home', 'YOU',
          `${homeLoc.ip} — ${[homeLoc.city, homeLoc.country].filter(Boolean).join(', ')} (your connection)`,
          { alwaysLabel: true }
        ));
      }

      updateStatus(list.length, located.length, unmapped);
      lastRenderKey = renderKey;
    } finally {
      refreshing = false;
    }
  }

  // ── Main render ───────────────────────────────────
  async function renderMap() {
    const wrap = document.getElementById('world-map-wrap');
    if (!wrap) return;

    wrap.innerHTML = '<div class="loading-row" style="justify-content:center;height:300px"><div class="spinner"></div><span>Loading world map…</span></div>';

    // ── Fetch real data ──
    let countries, bordersMesh, coastlineMesh;
    try {
      const res = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-50m.json');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const topo = await res.json();
      countries = topojson.feature(topo, topo.objects.countries);
      bordersMesh = topojson.mesh(topo, topo.objects.countries, (a, b) => a !== b);
      coastlineMesh = topojson.mesh(topo, topo.objects.countries, (a, b) => a === b);
    } catch (err) {
      console.error('World map load failed:', err);
      wrap.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:300px;color:var(--red);font-size:12px;font-family:var(--f-mono)">⚠ Failed to load map data — check network</div>';
      return;
    }

    // ── Create SVG ──
    svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('class', 'world-map-svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);

    const defs = document.createElementNS(NS, 'defs');
    defs.innerHTML = `
      <radialGradient id="map-glow-bg" cx="50%" cy="45%" r="45%">
        <stop offset="0%" stop-color="rgba(69,137,255,0.04)"/>
        <stop offset="100%" stop-color="rgba(69,137,255,0)"/>
      </radialGradient>
      <filter id="glow-arc">
        <feGaussianBlur stdDeviation="1.5" result="blur"/>
        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
      <filter id="glow-city">
        <feGaussianBlur stdDeviation="2.5" result="blur"/>
        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
    `;
    svg.appendChild(defs);

    const bgRect = document.createElementNS(NS, 'rect');
    bgRect.setAttribute('width', W); bgRect.setAttribute('height', H);
    bgRect.setAttribute('fill', 'url(#map-glow-bg)');
    svg.appendChild(bgRect);

    // ── Graticule grid ──
    const gridG = document.createElementNS(NS, 'g');
    gridG.setAttribute('stroke', 'rgba(69,137,255,0.022)');
    gridG.setAttribute('stroke-width', '0.35');
    gridG.setAttribute('fill', 'none');
    [-40, -20, 0, 20, 40, 60].forEach(lat => {
      const l = document.createElementNS(NS, 'line');
      l.setAttribute('x1', 0); l.setAttribute('x2', W);
      l.setAttribute('y1', py(lat).toFixed(1)); l.setAttribute('y2', py(lat).toFixed(1));
      if (lat === 0) {
        l.setAttribute('stroke', 'rgba(69,137,255,0.05)');
        l.setAttribute('stroke-dasharray', '8,5');
        l.setAttribute('stroke-width', '0.5');
      }
      gridG.appendChild(l);
    });
    for (let lon = -150; lon <= 150; lon += 30) {
      const l = document.createElementNS(NS, 'line');
      l.setAttribute('x1', px(lon).toFixed(1)); l.setAttribute('x2', px(lon).toFixed(1));
      l.setAttribute('y1', 0); l.setAttribute('y2', H);
      gridG.appendChild(l);
    }
    svg.appendChild(gridG);

    // ── Country fills ──
    const fills = [
      'rgba(69,137,255,0.045)',
      'rgba(69,137,255,0.06)',
      'rgba(69,137,255,0.035)',
      'rgba(69,137,255,0.055)',
    ];
    const landG = document.createElementNS(NS, 'g');
    countries.features.forEach((feature, idx) => {
      const d = geoToSVGPath(feature.geometry);
      if (!d) return;
      const path = document.createElementNS(NS, 'path');
      path.setAttribute('d', d);
      path.setAttribute('fill', fills[idx % fills.length]);
      path.setAttribute('stroke', 'none');
      path.classList.add('map-country');
      landG.appendChild(path);
    });
    svg.appendChild(landG);

    // ── Internal borders ──
    const bordersD = geoToSVGPath(bordersMesh);
    if (bordersD) {
      const bp = document.createElementNS(NS, 'path');
      bp.setAttribute('d', bordersD);
      bp.setAttribute('fill', 'none');
      bp.setAttribute('stroke', 'rgba(69,137,255,0.1)');
      bp.setAttribute('stroke-width', '0.3');
      bp.setAttribute('stroke-linejoin', 'round');
      bp.classList.add('map-borders');
      svg.appendChild(bp);
    }

    // ── Coastlines ──
    const coastD = geoToSVGPath(coastlineMesh);
    if (coastD) {
      const cp = document.createElementNS(NS, 'path');
      cp.setAttribute('d', coastD);
      cp.setAttribute('fill', 'none');
      cp.setAttribute('stroke', 'rgba(69,137,255,0.25)');
      cp.setAttribute('stroke-width', '0.6');
      cp.setAttribute('stroke-linejoin', 'round');
      cp.classList.add('map-coast');
      svg.appendChild(cp);
    }

    // ── Data layers (filled by updateMarkers) ──
    arcG = document.createElementNS(NS, 'g');
    svg.appendChild(arcG);
    markerG = document.createElementNS(NS, 'g');
    svg.appendChild(markerG);

    // ── Mount ──
    wrap.innerHTML = '';
    wrap.appendChild(svg);

    // Empty state + status chip (HTML overlays)
    emptyEl = document.createElement('div');
    emptyEl.className = 'map-overlay-msg';
    emptyEl.style.display = 'none';
    emptyEl.innerHTML = `
      <div class="map-overlay-title">No threat origins to map yet</div>
      <div class="map-overlay-sub">Block an IP (IP Lookup → Add to Blocklist) and its real location appears here</div>`;
    wrap.appendChild(emptyEl);

    statusEl = document.createElement('div');
    statusEl.className = 'map-status';
    statusEl.style.display = 'none';
    wrap.appendChild(statusEl);

    // ── Live data: home node first, then blocklist ──
    homeLoc = await locateSelf();
    await updateMarkers(true);

    // Poll for blocklist changes (cheap: cached geo + render-key diff)
    setInterval(() => updateMarkers(false), 5000);
    window.refreshWorldMap = () => updateMarkers(true);
  }

  // ── Init ──
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', renderMap);
  } else {
    renderMap();
  }
})();
