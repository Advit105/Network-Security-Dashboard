// ═══════════════════════════════════════════════════
//  world_map.js — Accurate SVG World Map
//  Fetches Natural Earth 110m countries TopoJSON
//  Uses topojson-client library for proper decoding
//  Equirectangular projection → 1000×500 SVG
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  const W = 1000, H = 500;

  // ── Equirectangular projection ────────────────────
  function px(lon) { return ((lon + 180) / 360) * W; }
  function py(lat) { return ((90 - lat) / 180) * H; }

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

  // ── City nodes ────────────────────────────────────
  const cities = [
    { lon: -122.42, lat: 37.77, code: 'SFO', cls: 'red' },
    { lon: -74.00,  lat: 40.71, code: 'NYC', cls: 'red' },
    { lon: -43.17,  lat: -22.90, code: 'GRU', cls: 'amber' },
    { lon: -0.12,   lat: 51.51, code: 'LHR', cls: '' },
    { lon: 37.62,   lat: 55.75, code: 'SVO', cls: '' },
    { lon: 116.40,  lat: 39.90, code: 'PEK', cls: 'green' },
    { lon: 72.88,   lat: 19.08, code: 'BOM', cls: 'amber' },
    { lon: 139.69,  lat: 35.69, code: 'NRT', cls: '' },
    { lon: 3.39,    lat: 6.45,  code: 'LOS', cls: 'red' },
    { lon: 28.04,   lat: -26.20, code: 'JNB', cls: 'green' },
    { lon: 151.21,  lat: -33.87, code: 'SYD', cls: '' },
    { lon: -99.13,  lat: 19.43, code: 'MEX', cls: '' },
    { lon: 13.41,   lat: 52.52, code: 'BER', cls: 'green' },
    { lon: 100.50,  lat: 13.76, code: 'BKK', cls: 'amber' },
    { lon: 103.82,  lat: 1.35,  code: 'SIN', cls: '' },
    { lon: 55.30,   lat: 25.27, code: 'DXB', cls: '' },
  ];

  // ── Attack arcs ───────────────────────────────────
  const attackArcs = [
    { from: 'SVO', to: 'LHR', color: '#ff4f6b', delay: 0 },
    { from: 'PEK', to: 'SFO', color: '#00e5ff', delay: -0.5 },
    { from: 'GRU', to: 'NYC', color: '#f59e0b', delay: -1 },
    { from: 'NRT', to: 'BOM', color: '#00d09c', delay: -1.5 },
    { from: 'JNB', to: 'LHR', color: '#7c3aed', delay: -2 },
    { from: 'LOS', to: 'PEK', color: '#ff4f6b', delay: -0.3 },
    { from: 'SYD', to: 'NRT', color: '#00e5ff', delay: -1.8 },
    { from: 'NYC', to: 'GRU', color: '#7c3aed', delay: -2.5 },
    { from: 'BKK', to: 'BER', color: '#f59e0b', delay: -3 },
    { from: 'DXB', to: 'SFO', color: '#00d09c', delay: -3.5 },
    { from: 'SIN', to: 'SVO', color: '#ff4f6b', delay: -1.2 },
    { from: 'MEX', to: 'LOS', color: '#00e5ff', delay: -2.8 },
  ];

  const NS = 'http://www.w3.org/2000/svg';
  const dotColors = { red: '#ff4f6b', amber: '#f59e0b', green: '#00d09c', '': '#00e5ff' };
  const glowColors = { red: 'rgba(255,79,107,0.18)', amber: 'rgba(245,158,11,0.18)', green: 'rgba(0,208,156,0.18)', '': 'rgba(0,229,255,0.15)' };

  // ── Main render ───────────────────────────────────
  async function renderMap() {
    const wrap = document.getElementById('world-map-wrap');
    if (!wrap) return;

    wrap.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:300px;color:var(--text-3);font-size:12px;font-family:var(--f-mono);gap:8px"><div class="status-dot"></div>Loading world map…</div>';

    // ── Fetch real data ──
    let countries, bordersMesh, coastlineMesh;
    try {
      const res = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-50m.json');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const topo = await res.json();
      countries = topojson.feature(topo, topo.objects.countries);
      // Internal borders (shared edges between countries)
      bordersMesh = topojson.mesh(topo, topo.objects.countries, (a, b) => a !== b);
      // Coastlines (outer edges only)
      coastlineMesh = topojson.mesh(topo, topo.objects.countries, (a, b) => a === b);
    } catch (err) {
      console.error('World map load failed:', err);
      wrap.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:300px;color:var(--red);font-size:12px;font-family:var(--f-mono)">⚠ Failed to load map data — check network</div>';
      return;
    }

    // ── Create SVG ──
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('class', 'world-map-svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);

    // Defs
    const defs = document.createElementNS(NS, 'defs');
    defs.innerHTML = `
      <radialGradient id="map-glow-bg" cx="50%" cy="45%" r="45%">
        <stop offset="0%" stop-color="rgba(0,229,255,0.04)"/>
        <stop offset="100%" stop-color="rgba(0,229,255,0)"/>
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

    // Background glow
    const bgRect = document.createElementNS(NS, 'rect');
    bgRect.setAttribute('width', W); bgRect.setAttribute('height', H);
    bgRect.setAttribute('fill', 'url(#map-glow-bg)');
    svg.appendChild(bgRect);

    // ── Graticule grid ──
    const gridG = document.createElementNS(NS, 'g');
    gridG.setAttribute('stroke', 'rgba(0,229,255,0.025)');
    gridG.setAttribute('stroke-width', '0.35');
    gridG.setAttribute('fill', 'none');
    [-60, -30, 0, 30, 60].forEach(lat => {
      const l = document.createElementNS(NS, 'line');
      l.setAttribute('x1', 0); l.setAttribute('x2', W);
      l.setAttribute('y1', py(lat)); l.setAttribute('y2', py(lat));
      if (lat === 0) {
        l.setAttribute('stroke', 'rgba(0,229,255,0.06)');
        l.setAttribute('stroke-dasharray', '8,5');
        l.setAttribute('stroke-width', '0.5');
      }
      gridG.appendChild(l);
    });
    for (let lon = -150; lon <= 180; lon += 30) {
      const l = document.createElementNS(NS, 'line');
      l.setAttribute('x1', px(lon)); l.setAttribute('x2', px(lon));
      l.setAttribute('y1', 0); l.setAttribute('y2', H);
      gridG.appendChild(l);
    }
    svg.appendChild(gridG);

    // ── Render country fills ──
    const fills = [
      'rgba(0,229,255,0.045)',
      'rgba(0,229,255,0.06)',
      'rgba(0,229,255,0.035)',
      'rgba(0,229,255,0.055)',
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

    // ── Internal country borders (thin, subtle) ──
    const bordersD = geoToSVGPath(bordersMesh);
    if (bordersD) {
      const bp = document.createElementNS(NS, 'path');
      bp.setAttribute('d', bordersD);
      bp.setAttribute('fill', 'none');
      bp.setAttribute('stroke', 'rgba(0,229,255,0.1)');
      bp.setAttribute('stroke-width', '0.3');
      bp.setAttribute('stroke-linejoin', 'round');
      svg.appendChild(bp);
    }

    // ── Coastline outline (brighter, on top) ──
    const coastD = geoToSVGPath(coastlineMesh);
    if (coastD) {
      const cp = document.createElementNS(NS, 'path');
      cp.setAttribute('d', coastD);
      cp.setAttribute('fill', 'none');
      cp.setAttribute('stroke', 'rgba(0,229,255,0.25)');
      cp.setAttribute('stroke-width', '0.6');
      cp.setAttribute('stroke-linejoin', 'round');
      svg.appendChild(cp);
    }

    // ── City markers (SVG layer) ──
    const cityG = document.createElementNS(NS, 'g');
    const cityMap = {};
    cities.forEach(c => {
      const x = px(c.lon), y = py(c.lat);
      cityMap[c.code] = { x, y };

      // Outer glow
      const glow = document.createElementNS(NS, 'circle');
      glow.setAttribute('cx', x); glow.setAttribute('cy', y);
      glow.setAttribute('r', '7');
      glow.setAttribute('fill', glowColors[c.cls] || glowColors['']);
      glow.setAttribute('filter', 'url(#glow-city)');
      cityG.appendChild(glow);

      // Inner dot
      const dot = document.createElementNS(NS, 'circle');
      dot.setAttribute('cx', x); dot.setAttribute('cy', y);
      dot.setAttribute('r', '2.5');
      dot.setAttribute('fill', dotColors[c.cls] || dotColors['']);
      cityG.appendChild(dot);

      // Label
      const txt = document.createElementNS(NS, 'text');
      txt.setAttribute('x', x); txt.setAttribute('y', y - 9);
      txt.setAttribute('text-anchor', 'middle');
      txt.setAttribute('fill', 'rgba(0,229,255,0.45)');
      txt.setAttribute('font-size', '7');
      txt.setAttribute('font-family', 'JetBrains Mono, monospace');
      txt.setAttribute('font-weight', '600');
      txt.textContent = c.code;
      cityG.appendChild(txt);
    });
    svg.appendChild(cityG);

    // ── Static attack arcs ──
    const arcG = document.createElementNS(NS, 'g');
    attackArcs.forEach(arc => {
      const a = cityMap[arc.from], b = cityMap[arc.to];
      if (!a || !b) return;
      const mx = (a.x + b.x) / 2;
      const my = (a.y + b.y) / 2 - Math.abs(a.x - b.x) * 0.15 - 25;
      const p = document.createElementNS(NS, 'path');
      p.setAttribute('d', `M${a.x.toFixed(1)},${a.y.toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}`);
      p.setAttribute('stroke', arc.color);
      p.setAttribute('stroke-width', '0.9');
      p.setAttribute('fill', 'none');
      p.setAttribute('filter', 'url(#glow-arc)');
      p.classList.add('atk-line');
      p.style.animationDelay = arc.delay + 's';
      arcG.appendChild(p);
    });
    svg.appendChild(arcG);

    // ── Mount ──
    wrap.innerHTML = '';
    wrap.appendChild(svg);

    // ── SVG pulsing rings (perfectly aligned, inside the SVG) ──
    const pulseG = document.createElementNS(NS, 'g');
    cities.forEach((c, idx) => {
      const x = px(c.lon), y = py(c.lat);
      const color = dotColors[c.cls] || dotColors[''];
      // Animated expanding ring
      const ring = document.createElementNS(NS, 'circle');
      ring.setAttribute('cx', x); ring.setAttribute('cy', y);
      ring.setAttribute('r', '3');
      ring.setAttribute('fill', 'none');
      ring.setAttribute('stroke', color);
      ring.setAttribute('stroke-width', '1');
      ring.setAttribute('opacity', '0.6');
      // SVG animate for pulse
      const animR = document.createElementNS(NS, 'animate');
      animR.setAttribute('attributeName', 'r');
      animR.setAttribute('from', '3'); animR.setAttribute('to', '10');
      animR.setAttribute('dur', '2s');
      animR.setAttribute('begin', (idx * 0.3 % 2).toFixed(1) + 's');
      animR.setAttribute('repeatCount', 'indefinite');
      ring.appendChild(animR);
      const animO = document.createElementNS(NS, 'animate');
      animO.setAttribute('attributeName', 'opacity');
      animO.setAttribute('from', '0.6'); animO.setAttribute('to', '0');
      animO.setAttribute('dur', '2s');
      animO.setAttribute('begin', (idx * 0.3 % 2).toFixed(1) + 's');
      animO.setAttribute('repeatCount', 'indefinite');
      ring.appendChild(animO);
      pulseG.appendChild(ring);
    });
    // Insert pulse rings BEFORE city dots so dots render on top
    svg.insertBefore(pulseG, cityG);

    // ── Dynamic random attack arcs ──
    setInterval(() => {
      const i = Math.floor(Math.random() * cities.length);
      let j = Math.floor(Math.random() * cities.length);
      if (i === j) j = (j + 1) % cities.length;
      const a = cityMap[cities[i].code], b = cityMap[cities[j].code];
      if (!a || !b) return;
      const mx = (a.x + b.x) / 2;
      const my = (a.y + b.y) / 2 - Math.abs(a.x - b.x) * 0.12 - 15;
      const colors = ['#ff4f6b', '#00e5ff', '#f59e0b', '#00d09c', '#7c3aed'];
      const color = colors[Math.floor(Math.random() * colors.length)];

      const p = document.createElementNS(NS, 'path');
      p.setAttribute('d', `M${a.x.toFixed(1)},${a.y.toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}`);
      p.setAttribute('stroke', color);
      p.setAttribute('stroke-width', '0.5');
      p.setAttribute('fill', 'none');
      p.setAttribute('filter', 'url(#glow-arc)');
      p.setAttribute('opacity', '0');
      p.style.transition = 'opacity 0.4s';
      arcG.appendChild(p);
      requestAnimationFrame(() => p.setAttribute('opacity', '0.7'));
      setTimeout(() => {
        p.setAttribute('opacity', '0');
        setTimeout(() => p.remove(), 500);
      }, 2000 + Math.random() * 2000);
    }, 2500);
  }

  // ── Init ──
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', renderMap);
  } else {
    renderMap();
  }
})();
