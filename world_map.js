// ═══════════════════════════════════════════════════
//  world_map.js — Realistic SVG World Map Renderer
//  Equirectangular projection mapped to 1000×500 viewBox
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  // ── Projection helpers: lon/lat → SVG x/y ─────────
  // viewBox = 0 0 1000 500
  // lon: -180..+180 → x: 0..1000
  // lat: +90..-90  → y: 0..500  (north=top)
  function lx(lon) { return ((lon + 180) / 360) * 1000; }
  function ly(lat) { return ((90 - lat) / 180) * 500; }

  // Convert array of [lon,lat] pairs to SVG path "d" string
  function toPath(coords) {
    return coords.map((p, i) => (i === 0 ? 'M' : 'L') + lx(p[0]).toFixed(1) + ',' + ly(p[1]).toFixed(1)).join(' ') + ' Z';
  }

  // ── Country / Region outline data (simplified Natural Earth) ───
  const regions = [
    // ─── North America ───
    { name: 'Canada', coords: [[-140, 60], [-130, 67], [-120, 70], [-110, 69], [-100, 65], [-95, 69], [-85, 70], [-80, 63], [-75, 62], [-70, 58], [-65, 50], [-60, 47], [-55, 50], [-52, 47], [-56, 45], [-60, 44], [-63, 45], [-67, 45], [-70, 43], [-75, 45], [-80, 43], [-83, 46], [-85, 49], [-90, 49], [-95, 49], [-100, 49], [-110, 49], [-120, 49], [-123, 49], [-125, 50], [-128, 52], [-130, 55], [-133, 57], [-137, 59], [-140, 60]] },
    { name: 'USA', coords: [[-125, 49], [-120, 49], [-110, 49], [-105, 49], [-100, 49], [-95, 49], [-90, 49], [-85, 46], [-83, 46], [-80, 43], [-75, 40], [-72, 41], [-70, 42], [-67, 45], [-68, 44], [-70, 43], [-73, 40], [-75, 38], [-76, 37], [-78, 35], [-80, 32], [-82, 30], [-84, 30], [-87, 30], [-90, 29], [-92, 29], [-95, 29], [-97, 26], [-100, 28], [-103, 29], [-105, 31], [-108, 31], [-111, 32], [-114, 32], [-117, 33], [-118, 34], [-120, 35], [-122, 37], [-124, 40], [-124, 42], [-124, 46], [-125, 49]] },
    { name: 'Mexico', coords: [[-117, 33], [-114, 32], [-111, 32], [-108, 31], [-105, 31], [-103, 29], [-100, 28], [-97, 26], [-95, 18], [-92, 15], [-90, 16], [-88, 16], [-87, 18], [-88, 20], [-90, 21], [-92, 19], [-95, 19], [-97, 20], [-100, 21], [-103, 23], [-105, 24], [-108, 26], [-110, 27], [-112, 29], [-114, 30], [-115, 31], [-117, 33]] },
    { name: 'Alaska', coords: [[-170, 54], [-165, 55], [-160, 58], [-155, 59], [-150, 60], [-148, 62], [-145, 63], [-142, 60], [-140, 60], [-138, 57], [-142, 56], [-148, 57], [-152, 58], [-155, 56], [-160, 55], [-163, 55], [-165, 54], [-168, 53], [-170, 54]] },
    { name: 'Greenland', coords: [[-55, 60], [-50, 62], [-45, 65], [-40, 68], [-35, 72], [-25, 74], [-18, 76], [-20, 78], [-25, 80], [-35, 82], [-45, 81], [-50, 78], [-55, 75], [-58, 72], [-60, 68], [-58, 64], [-55, 60]] },

    // ─── South America ───
    { name: 'Brazil', coords: [[-45, -2], [-42, -3], [-38, -5], [-35, -6], [-35, -10], [-37, -12], [-38, -15], [-40, -18], [-42, -22], [-44, -23], [-48, -25], [-50, -27], [-52, -28], [-54, -30], [-55, -32], [-54, -33], [-52, -32], [-50, -30], [-48, -28], [-50, -25], [-52, -23], [-55, -22], [-58, -20], [-60, -15], [-62, -13], [-65, -10], [-68, -12], [-70, -10], [-73, -8], [-72, -5], [-70, -2], [-68, 0], [-65, 2], [-62, 3], [-60, 5], [-58, 4], [-55, 3], [-52, 2], [-50, 0], [-48, -1], [-45, -2]] },
    { name: 'Argentina', coords: [[-70, -20], [-68, -22], [-67, -24], [-65, -28], [-65, -32], [-65, -35], [-67, -38], [-68, -40], [-69, -42], [-71, -44], [-72, -46], [-74, -48], [-74, -50], [-72, -52], [-70, -54], [-68, -55], [-65, -54], [-64, -52], [-62, -48], [-60, -42], [-58, -38], [-56, -35], [-55, -32], [-54, -30], [-55, -28], [-58, -25], [-60, -22], [-62, -20], [-65, -20], [-68, -20], [-70, -20]] },
    { name: 'Colombia', coords: [[-78, 2], [-77, 4], [-75, 6], [-73, 8], [-72, 10], [-73, 12], [-75, 11], [-77, 9], [-78, 7], [-80, 5], [-78, 2], [-76, 0], [-73, -2], [-70, -2], [-68, 0], [-68, 2], [-70, 4], [-72, 5], [-75, 5], [-78, 2]] },

    // ─── Europe ───
    { name: 'UK', coords: [[-6, 50], [-5, 52], [-4, 54], [-5, 56], [-6, 58], [-3, 58], [-2, 56], [0, 53], [1, 52], [0, 51], [-1, 50], [-3, 50], [-6, 50]] },
    { name: 'France', coords: [[-2, 48], [0, 49], [2, 51], [3, 50], [5, 49], [7, 48], [7, 46], [6, 44], [3, 43], [0, 43], [-2, 44], [-3, 47], [-2, 48]] },
    { name: 'Spain', coords: [[-9, 43], [-6, 43], [-2, 44], [0, 43], [3, 43], [3, 40], [1, 38], [-1, 37], [-5, 36], [-7, 37], [-9, 38], [-10, 40], [-9, 43]] },
    { name: 'Germany', coords: [[6, 48], [7, 48], [8, 50], [9, 51], [10, 52], [10, 54], [11, 55], [12, 54], [14, 53], [15, 51], [14, 49], [13, 48], [12, 48], [10, 47], [8, 47], [6, 48]] },
    { name: 'Italy', coords: [[7, 44], [8, 46], [10, 46], [12, 46], [14, 46], [16, 42], [18, 40], [16, 38], [14, 37], [12, 38], [10, 40], [8, 44], [7, 44]] },
    { name: 'Scandinavia', coords: [[5, 58], [6, 60], [7, 62], [8, 64], [10, 66], [12, 68], [15, 69], [18, 70], [20, 69], [22, 68], [25, 66], [28, 64], [30, 62], [30, 60], [25, 58], [20, 56], [15, 56], [10, 57], [5, 58]] },

    // ─── Africa ───
    { name: 'NorthAfrica', coords: [[-17, 15], [-12, 16], [-8, 18], [-5, 20], [-2, 22], [0, 25], [2, 28], [5, 30], [8, 32], [10, 35], [12, 37], [15, 35], [18, 33], [20, 32], [25, 30], [30, 28], [32, 30], [35, 30], [35, 25], [32, 22], [30, 20], [28, 18], [25, 15], [20, 12], [15, 10], [10, 8], [5, 8], [0, 10], [-5, 12], [-10, 14], [-15, 15], [-17, 15]] },
    { name: 'WestAfrica', coords: [[-17, 15], [-15, 12], [-12, 8], [-10, 5], [-8, 5], [-5, 5], [-3, 6], [0, 6], [3, 6], [5, 5], [5, 8], [8, 8], [10, 8], [10, 5], [8, 3], [5, 3], [3, 3], [0, 4], [-3, 5], [-5, 6], [-8, 5], [-10, 5], [-12, 5], [-15, 8], [-17, 10], [-17, 15]] },
    { name: 'EastAfrica', coords: [[30, 10], [32, 8], [34, 5], [36, 2], [38, 0], [40, -2], [42, -5], [40, -8], [38, -10], [35, -12], [32, -10], [30, -8], [28, -5], [25, 0], [28, 5], [30, 8], [30, 10]] },
    { name: 'SouthAfrica', coords: [[17, -30], [18, -33], [20, -35], [22, -34], [25, -34], [27, -33], [30, -32], [32, -30], [33, -28], [32, -25], [30, -22], [28, -20], [25, -18], [22, -18], [20, -20], [18, -22], [16, -25], [15, -28], [17, -30]] },
    { name: 'CentralAfrica', coords: [[8, 5], [10, 3], [12, 2], [15, 0], [18, -2], [20, -5], [22, -8], [25, -10], [28, -12], [30, -15], [28, -18], [25, -18], [22, -15], [20, -12], [18, -10], [15, -5], [12, 0], [10, 2], [8, 3], [8, 5]] },

    // ─── Asia ───
    { name: 'Russia', coords: [[28, 72], [35, 72], [45, 70], [55, 68], [65, 70], [75, 72], [85, 74], [95, 72], [105, 70], [115, 68], [125, 66], [135, 65], [140, 62], [145, 60], [150, 58], [155, 55], [160, 52], [165, 55], [170, 58], [175, 62], [180, 65], [180, 55], [175, 52], [170, 48], [165, 45], [160, 48], [155, 50], [150, 52], [148, 54], [145, 55], [140, 52], [135, 50], [130, 48], [125, 45], [120, 42], [115, 43], [110, 45], [105, 48], [100, 50], [95, 52], [90, 55], [85, 55], [80, 55], [75, 55], [70, 55], [65, 55], [60, 52], [55, 50], [50, 48], [45, 46], [40, 44], [35, 45], [30, 48], [28, 52], [25, 55], [20, 58], [22, 60], [25, 65], [28, 72]] },
    { name: 'China', coords: [[75, 40], [78, 38], [80, 35], [85, 33], [88, 30], [92, 28], [95, 25], [100, 22], [105, 22], [108, 20], [110, 22], [115, 23], [118, 25], [120, 28], [122, 30], [125, 35], [128, 38], [130, 42], [128, 45], [125, 48], [120, 50], [115, 50], [110, 48], [105, 48], [100, 48], [95, 48], [90, 45], [85, 42], [80, 42], [75, 40]] },
    { name: 'India', coords: [[68, 30], [70, 28], [72, 25], [73, 22], [74, 20], [75, 18], [76, 15], [78, 10], [80, 8], [82, 10], [84, 12], [85, 15], [86, 18], [88, 20], [90, 22], [92, 24], [92, 27], [90, 28], [88, 26], [85, 22], [82, 18], [80, 15], [78, 12], [78, 15], [78, 18], [78, 20], [76, 22], [74, 25], [72, 28], [70, 30], [68, 30]] },
    { name: 'MiddleEast', coords: [[35, 30], [38, 32], [40, 35], [42, 38], [45, 38], [48, 35], [50, 32], [52, 28], [55, 25], [58, 22], [55, 20], [52, 22], [50, 25], [48, 28], [45, 30], [42, 32], [40, 30], [38, 28], [36, 25], [34, 22], [32, 20], [30, 22], [32, 25], [34, 28], [35, 30]] },
    { name: 'Japan', coords: [[130, 32], [132, 34], [134, 36], [136, 38], [138, 40], [140, 42], [141, 44], [142, 45], [142, 42], [140, 38], [138, 35], [136, 33], [134, 32], [132, 31], [130, 32]] },
    { name: 'SEAsia', coords: [[98, 18], [100, 15], [102, 12], [104, 10], [106, 8], [108, 10], [110, 12], [112, 15], [114, 18], [116, 15], [118, 12], [120, 10], [118, 8], [116, 5], [114, 3], [112, 2], [110, 0], [108, -2], [106, 0], [104, 2], [102, 5], [100, 8], [98, 10], [96, 12], [98, 15], [98, 18]] },
    { name: 'Korea', coords: [[125, 35], [126, 37], [127, 38], [128, 38], [129, 37], [130, 35], [129, 34], [128, 33], [127, 33], [126, 34], [125, 35]] },

    // ─── Oceania ───
    { name: 'Australia', coords: [[115, -35], [118, -34], [120, -32], [122, -30], [125, -28], [128, -25], [130, -22], [132, -15], [134, -12], [136, -12], [138, -15], [140, -18], [142, -15], [145, -15], [148, -18], [150, -22], [152, -25], [153, -28], [153, -30], [152, -33], [150, -35], [148, -38], [145, -39], [142, -38], [140, -36], [138, -35], [135, -34], [132, -32], [130, -30], [128, -32], [125, -35], [122, -35], [120, -35], [118, -35], [115, -35]] },
    { name: 'NewZealand', coords: [[165, -35], [167, -37], [170, -38], [172, -40], [174, -42], [176, -44], [175, -46], [173, -45], [172, -43], [170, -40], [168, -38], [166, -36], [165, -35]] },
    { name: 'Papua', coords: [[140, -2], [142, -4], [144, -5], [146, -6], [148, -7], [150, -6], [152, -5], [150, -3], [148, -2], [146, -2], [144, -1], [142, -1], [140, -2]] },

    // ─── Islands ───
    { name: 'Iceland', coords: [[-24, 64], [-22, 65], [-18, 66], [-15, 66], [-14, 65], [-16, 64], [-20, 63], [-24, 64]] },
    { name: 'SriLanka', coords: [[80, 7], [81, 8], [82, 8], [82, 6], [81, 5], [80, 6], [80, 7]] },
    { name: 'Philippines', coords: [[118, 15], [120, 18], [122, 18], [124, 16], [125, 12], [124, 10], [122, 8], [120, 10], [118, 12], [118, 15]] },
    { name: 'Taiwan', coords: [[120, 22], [121, 25], [122, 25], [121, 23], [120, 22]] },
    { name: 'Cuba', coords: [[-85, 22], [-82, 23], [-80, 22], [-77, 20], [-75, 20], [-78, 21], [-82, 22], [-85, 22]] },
    { name: 'Madagascar', coords: [[44, -13], [46, -15], [48, -18], [49, -20], [49, -24], [47, -25], [45, -23], [44, -20], [43, -17], [43, -14], [44, -13]] },
  ];

  // ── City nodes (lon, lat, name, color-class) ──────
  const cities = [
    { lon: -122.42, lat: 37.77, name: 'San Francisco', code: 'SFO', cls: 'red' },
    { lon: -74.00, lat: 40.71, name: 'New York', code: 'NYC', cls: 'red' },
    { lon: -43.17, lat: -22.90, name: 'São Paulo', code: 'GRU', cls: 'amber' },
    { lon: -0.12, lat: 51.51, name: 'London', code: 'LHR', cls: '' },
    { lon: 37.62, lat: 55.75, name: 'Moscow', code: 'SVO', cls: '' },
    { lon: 116.40, lat: 39.90, name: 'Beijing', code: 'PEK', cls: 'green' },
    { lon: 72.88, lat: 19.08, name: 'Mumbai', code: 'BOM', cls: 'amber' },
    { lon: 139.69, lat: 35.69, name: 'Tokyo', code: 'NRT', cls: '' },
    { lon: 3.39, lat: 6.45, name: 'Lagos', code: 'LOS', cls: 'red' },
    { lon: 28.04, lat: -26.20, name: 'Johannesburg', code: 'JNB', cls: 'green' },
    { lon: 151.21, lat: -33.87, name: 'Sydney', code: 'SYD', cls: '' },
    { lon: -99.13, lat: 19.43, name: 'Mexico City', code: 'MEX', cls: '' },
    { lon: 13.41, lat: 52.52, name: 'Berlin', code: 'BER', cls: 'green' },
    { lon: 100.50, lat: 13.76, name: 'Bangkok', code: 'BKK', cls: 'amber' },
    { lon: 103.82, lat: 1.35, name: 'Singapore', code: 'SIN', cls: '' },
    { lon: 55.30, lat: 25.27, name: 'Dubai', code: 'DXB', cls: '' },
  ];

  // ── Attack arc definitions ────────────────────────
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

  // ── Build SVG ─────────────────────────────────────
  function renderMap() {
    const wrap = document.getElementById('world-map-wrap');
    if (!wrap) return;

    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('class', 'world-map-svg');
    svg.setAttribute('viewBox', '0 0 1000 500');
    svg.setAttribute('xmlns', NS);

    // ── Defs ──
    const defs = document.createElementNS(NS, 'defs');
    defs.innerHTML = `
      <radialGradient id="map-glow-center" cx="50%" cy="50%" r="40%">
        <stop offset="0%" stop-color="rgba(0,229,255,0.05)"/>
        <stop offset="100%" stop-color="rgba(0,229,255,0)"/>
      </radialGradient>
      <filter id="glow-line">
        <feGaussianBlur stdDeviation="1.5" result="blur"/>
        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
      <filter id="city-glow">
        <feGaussianBlur stdDeviation="3" result="blur"/>
        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
    `;
    svg.appendChild(defs);

    // ── Background glow ──
    const bg = document.createElementNS(NS, 'rect');
    bg.setAttribute('width', '1000'); bg.setAttribute('height', '500');
    bg.setAttribute('fill', 'url(#map-glow-center)');
    svg.appendChild(bg);

    // ── Graticule grid ──
    const grid = document.createElementNS(NS, 'g');
    grid.setAttribute('stroke', 'rgba(0,229,255,0.03)');
    grid.setAttribute('stroke-width', '0.4');
    grid.setAttribute('fill', 'none');
    // Latitude lines every 30°
    [-60, -30, 0, 30, 60].forEach(lat => {
      const line = document.createElementNS(NS, 'line');
      line.setAttribute('x1', '0'); line.setAttribute('x2', '1000');
      line.setAttribute('y1', ly(lat)); line.setAttribute('y2', ly(lat));
      if (lat === 0) {
        line.setAttribute('stroke', 'rgba(0,229,255,0.07)');
        line.setAttribute('stroke-dasharray', '6,4');
        line.setAttribute('stroke-width', '0.6');
      }
      grid.appendChild(line);
    });
    // Longitude lines every 30°
    for (let lon = -150; lon <= 180; lon += 30) {
      const line = document.createElementNS(NS, 'line');
      line.setAttribute('x1', lx(lon)); line.setAttribute('x2', lx(lon));
      line.setAttribute('y1', '0'); line.setAttribute('y2', '500');
      grid.appendChild(line);
    }
    svg.appendChild(grid);

    // ── Country outlines ──
    const lands = document.createElementNS(NS, 'g');
    regions.forEach(r => {
      const path = document.createElementNS(NS, 'path');
      path.setAttribute('d', toPath(r.coords));
      path.setAttribute('fill', 'rgba(0,229,255,0.035)');
      path.setAttribute('stroke', 'rgba(0,229,255,0.18)');
      path.setAttribute('stroke-width', '0.8');
      path.setAttribute('stroke-linejoin', 'round');
      path.classList.add('map-country');
      path.dataset.name = r.name;
      lands.appendChild(path);
    });
    svg.appendChild(lands);

    // ── City markers ──
    const cityGroup = document.createElementNS(NS, 'g');
    const cityMap = {};
    cities.forEach(c => {
      const x = lx(c.lon), y = ly(c.lat);
      cityMap[c.code] = { x, y };

      // Glow circle
      const glow = document.createElementNS(NS, 'circle');
      glow.setAttribute('cx', x); glow.setAttribute('cy', y); glow.setAttribute('r', '6');
      const glowColors = { red: 'rgba(255,79,107,0.15)', amber: 'rgba(245,158,11,0.15)', green: 'rgba(0,208,156,0.15)', '': 'rgba(0,229,255,0.12)' };
      glow.setAttribute('fill', glowColors[c.cls] || glowColors['']);
      glow.setAttribute('filter', 'url(#city-glow)');
      cityGroup.appendChild(glow);

      // Inner dot
      const dot = document.createElementNS(NS, 'circle');
      dot.setAttribute('cx', x); dot.setAttribute('cy', y); dot.setAttribute('r', '2.2');
      const dotColors = { red: '#ff4f6b', amber: '#f59e0b', green: '#00d09c', '': '#00e5ff' };
      dot.setAttribute('fill', dotColors[c.cls] || dotColors['']);
      cityGroup.appendChild(dot);

      // Label
      const label = document.createElementNS(NS, 'text');
      label.setAttribute('x', x); label.setAttribute('y', y - 7);
      label.setAttribute('text-anchor', 'middle');
      label.setAttribute('fill', 'rgba(0,229,255,0.4)');
      label.setAttribute('font-size', '6.5');
      label.setAttribute('font-family', 'JetBrains Mono, monospace');
      label.setAttribute('font-weight', '600');
      label.textContent = c.code;
      cityGroup.appendChild(label);
    });
    svg.appendChild(cityGroup);

    // ── Attack arcs ──
    const arcsGroup = document.createElementNS(NS, 'g');
    attackArcs.forEach(arc => {
      const from = cityMap[arc.from], to = cityMap[arc.to];
      if (!from || !to) return;
      const mx = (from.x + to.x) / 2;
      const my = (from.y + to.y) / 2 - Math.abs(from.x - to.x) * 0.15 - 30;

      const path = document.createElementNS(NS, 'path');
      path.setAttribute('d', `M${from.x},${from.y} Q${mx},${my} ${to.x},${to.y}`);
      path.setAttribute('stroke', arc.color);
      path.setAttribute('stroke-width', '0.8');
      path.setAttribute('fill', 'none');
      path.setAttribute('filter', 'url(#glow-line)');
      path.classList.add('atk-line');
      path.style.animationDelay = arc.delay + 's';
      arcsGroup.appendChild(path);
    });
    svg.appendChild(arcsGroup);

    // Remove old SVG + attack dots
    wrap.innerHTML = '';
    wrap.appendChild(svg);

    // ── HTML attack dots (positioned over the SVG) ──
    cities.forEach(c => {
      const x = (lx(c.lon) / 1000) * 100;
      const y = (ly(c.lat) / 500) * 100;
      const dot = document.createElement('div');
      dot.className = 'atk-dot' + (c.cls ? ' ' + c.cls : '');
      dot.style.left = x + '%';
      dot.style.top = y + '%';
      dot.style.animationDelay = (Math.random() * 2).toFixed(1) + 's';
      const label = document.createElement('span');
      label.className = 'atk-label';
      label.textContent = c.code;
      dot.appendChild(label);
      wrap.appendChild(dot);
    });

    // ── Dynamic attack events (random arcs that appear/disappear) ──
    setInterval(() => {
      const i = Math.floor(Math.random() * cities.length);
      const j = Math.floor(Math.random() * cities.length);
      if (i === j) return;
      const from = cityMap[cities[i].code], to = cityMap[cities[j].code];
      if (!from || !to) return;
      const mx = (from.x + to.x) / 2;
      const my = (from.y + to.y) / 2 - Math.abs(from.x - to.x) * 0.12 - 20;
      const colors = ['#ff4f6b', '#00e5ff', '#f59e0b', '#00d09c', '#7c3aed'];
      const color = colors[Math.floor(Math.random() * colors.length)];

      const path = document.createElementNS(NS, 'path');
      path.setAttribute('d', `M${from.x},${from.y} Q${mx},${my} ${to.x},${to.y}`);
      path.setAttribute('stroke', color);
      path.setAttribute('stroke-width', '0.6');
      path.setAttribute('fill', 'none');
      path.setAttribute('filter', 'url(#glow-line)');
      path.setAttribute('opacity', '0');
      path.style.transition = 'opacity 0.5s';
      arcsGroup.appendChild(path);
      requestAnimationFrame(() => path.setAttribute('opacity', '0.7'));
      setTimeout(() => {
        path.setAttribute('opacity', '0');
        setTimeout(() => path.remove(), 600);
      }, 2500 + Math.random() * 2000);
    }, 3000);
  }

  // ── Initialize ──
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', renderMap);
  } else {
    renderMap();
  }
})();
