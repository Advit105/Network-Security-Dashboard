// ═══════════════════════════════════════════════════
//  facts.js — live "threat facts" engine
//  Feeds two surfaces on the dashboard:
//    • #facts-text  — the LIVE FACTS ticker strip
//    • #hero-fact   — the rotating line in the hero
//
//  Every fact is derived from real, changing data:
//    - NVD weekly CVE count + newest / most-severe CVE
//      (reused from cve_feed.js via window.SentinelCVE —
//       no second NVD call, so we don't trip its rate limit)
//    - EPSS: the single most-exploitable CVE on earth right now
//    - Onionoo: live Tor relay + bridge counts
//    - your blocklist (localStorage) and this session
//  The strip rotates every few seconds; the underlying
//  network data re-fetches on an interval, so the facts
//  genuinely drift over time — nothing here is hardcoded.
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  const REDUCED = matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Live data caches, refreshed on their own cadences
  const live = { epssTop: null, tor: null };

  // ── Real fetches (keyless, CORS-open — verified) ──
  async function fetchEpssTop() {
    try {
      const r = await fetch('https://api.first.org/data/v1/epss?order=!epss&limit=1');
      if (!r.ok) return;
      const d = (await r.json()).data?.[0];
      if (d) live.epssTop = { cve: d.cve, pct: Math.round(parseFloat(d.epss) * 100) };
    } catch { /* fact simply omitted until it succeeds */ }
  }

  async function fetchTor() {
    try {
      const r = await fetch('https://onionoo.torproject.org/summary?running=true&limit=1');
      if (!r.ok) return;
      const d = await r.json();
      const relays  = (d.relays_truncated  || 0) + (d.relays  ? d.relays.length  : 0);
      const bridges = (d.bridges_truncated || 0) + (d.bridges ? d.bridges.length : 0);
      if (relays) live.tor = { relays, bridges };
    } catch { /* omitted */ }
  }

  // ── Helpers ──
  const nf = (n) => Number(n).toLocaleString();

  function loadBlocklist() {
    try { return JSON.parse(localStorage.getItem('sentinelx_blocklist')) || []; }
    catch { return []; }
  }

  function sessionUptime() {
    const el = document.getElementById('dash-uptime');
    return el ? el.textContent : null;
  }

  // ── Build the current fact pool from whatever is available ──
  function buildFacts() {
    const out = [];
    const cve = window.SentinelCVE;

    if (cve && cve.total != null) {
      out.push(`📡 ${nf(cve.total)} CVEs published across the NVD in the last 7 days`);
    }
    if (cve && cve.list && cve.list.length) {
      const list = cve.list;
      const newest = list.reduce((a, b) => new Date(a.published) > new Date(b.published) ? a : b);
      out.push(`🆕 Newest tracked vulnerability: ${newest.id}${newest.cvss != null ? ` (CVSS ${newest.cvss.toFixed(1)})` : ''}`);

      const top = list.reduce((a, b) => (b.cvss || 0) > (a.cvss || 0) ? b : a);
      if (top.cvss != null) out.push(`🎯 Highest-scoring CVE this week: ${top.id} at CVSS ${top.cvss.toFixed(1)}`);

      const crit = list.filter(c => c.cvss >= 9.0).length;
      if (crit) out.push(`🔴 ${crit} critical-severity CVE${crit === 1 ? '' : 's'} in the weekly feed`);

      const kev = list.filter(c => c.kev);
      if (kev.length) out.push(`⚠ ${kev[0].id} is on CISA's Known-Exploited list — actively exploited in the wild`);

      const epssTop = list.filter(c => c.epss != null).sort((a, b) => b.epss - a.epss)[0];
      if (epssTop) out.push(`📈 Most exploitable this week: ${epssTop.id} at ${(epssTop.epss * 100).toFixed(0)}% EPSS`);
    }

    if (live.epssTop) out.push(`🌐 Highest exploitation odds on earth right now: ${live.epssTop.cve} at ${live.epssTop.pct}% EPSS`);
    if (live.tor) out.push(`🧅 ${nf(live.tor.relays)} Tor relays and ${nf(live.tor.bridges)} bridges are online worldwide`);

    const bl = loadBlocklist();
    if (bl.length) {
      const c = bl.filter(e => e.severity === 'danger').length;
      out.push(`🛡 You're blocking ${bl.length} IP${bl.length === 1 ? '' : 's'}${c ? ` — ${c} marked critical` : ''}`);
    } else {
      out.push(`🛡 Your blocklist is empty — block an IP from any tool to rank it in Top Threat Origins`);
    }

    const ipEl = document.getElementById('dash-myip');
    if (ipEl && ipEl.textContent && !/detect/i.test(ipEl.textContent)) {
      out.push(`📍 Your public IP this session: ${ipEl.textContent}`);
    }
    const up = sessionUptime();
    if (up && up !== '0s') out.push(`⏱ Console session uptime: ${up}`);

    return out;
  }

  // ── Rotation across the two surfaces ──
  let facts = [];
  let stripIdx = 0, heroIdx = 1;
  const stripText = () => document.getElementById('facts-text');
  const heroText  = () => document.getElementById('hero-fact');
  const dotsWrap  = () => document.getElementById('facts-dots');

  function renderDots() {
    const w = dotsWrap();
    if (!w) return;
    const n = Math.min(facts.length, 8);
    w.innerHTML = Array.from({ length: n }, (_, i) =>
      `<span class="facts-dot${i === stripIdx % n ? ' on' : ''}"></span>`).join('');
  }

  function swap(el, text) {
    if (!el) return;
    if (REDUCED) { el.textContent = text; return; }
    el.style.opacity = '0';
    el.style.transform = 'translateY(4px)';
    setTimeout(() => {
      el.textContent = text;
      el.style.opacity = '1';
      el.style.transform = 'translateY(0)';
    }, 260);
  }

  function rotate() {
    if (!facts.length) return;
    stripIdx = (stripIdx + 1) % facts.length;
    swap(stripText(), facts[stripIdx]);
    renderDots();
    if (heroText() && facts.length > 1) {
      heroIdx = (heroIdx + 1) % facts.length;
      if (heroIdx === stripIdx) heroIdx = (heroIdx + 1) % facts.length;
      swap(heroText(), facts[heroIdx]);
    }
  }

  function rebuild() {
    const next = buildFacts();
    if (!next.length) return;
    facts = next;
    if (stripIdx >= facts.length) stripIdx = 0;
    // Paint immediately the first time (no fade) so nothing sits empty
    const st = stripText();
    if (st && !st.textContent) { st.textContent = facts[stripIdx]; st.style.opacity = '1'; }
    const ht = heroText();
    if (ht && !ht.textContent) { ht.textContent = facts[Math.min(1, facts.length - 1)]; ht.style.opacity = '1'; }
    renderDots();
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!stripText() && !heroText()) return;

    rebuild();                                   // seed from local/session data instantly
    Promise.all([fetchEpssTop(), fetchTor()]).then(rebuild);

    // Rebuild the pool when the shared CVE data lands / refreshes
    window.addEventListener('sentinel-cve', rebuild);

    if (!REDUCED) setInterval(rotate, 5000);     // visible rotation
    setInterval(rebuild, 20000);                 // fold in fresh local/session facts
    setInterval(() => {                          // re-pull network facts periodically
      Promise.all([fetchEpssTop(), fetchTor()]).then(rebuild);
    }, 4 * 60 * 1000);
  });
})();
