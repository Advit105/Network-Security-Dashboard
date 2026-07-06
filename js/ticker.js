// ═══════════════════════════════════════════════════
//  ticker.js — live threat-intel marquee on the dashboard.
//  Real data only: the last 7 days of CVEs from the NVD, ranked by CVSS.
//  Pauses on hover; clicking any item jumps to the CVE Feed page.
//  If the NVD is unreachable the strip simply stays hidden — never fake.
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  const SEV = (cvss) => {
    if (cvss == null) return { label: '—', color: 'var(--text-3)' };
    if (cvss >= 9) return { label: 'CRITICAL', color: 'var(--red)' };
    if (cvss >= 7) return { label: 'HIGH', color: 'var(--amber)' };
    if (cvss >= 4) return { label: 'MEDIUM', color: 'var(--cyan)' };
    return { label: 'LOW', color: 'var(--green)' };
  };

  function extractCVSS(v) {
    const m = v.cve?.metrics || {};
    return m.cvssMetricV31?.[0]?.cvssData?.baseScore
        ?? m.cvssMetricV30?.[0]?.cvssData?.baseScore
        ?? m.cvssMetricV2?.[0]?.cvssData?.baseScore
        ?? null;
  }

  async function load() {
    const wrap = document.getElementById('intel-ticker');
    const track = document.getElementById('ticker-track');
    if (!wrap || !track) return;

    let items;
    try {
      const now = new Date();
      const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        + `?pubStartDate=${weekAgo.toISOString().split('.')[0]}.000`
        + `&pubEndDate=${now.toISOString().split('.')[0]}.000`
        + '&resultsPerPage=15';
      const res = await fetch(url);
      if (!res.ok) return;
      const data = await res.json();
      items = (data.vulnerabilities || [])
        .map((v) => ({ id: v.cve?.id, cvss: extractCVSS(v) }))
        .filter((c) => c.id)
        .sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
    } catch {
      return; // offline / rate-limited → no ticker, no fakes
    }
    if (!items.length) return;

    const html = items.map((c) => {
      const s = SEV(c.cvss);
      return `<span class="ticker-item" data-page="cve">
        <span class="ticker-sev" style="background:${s.color}"></span>
        <span>${c.id}</span>
        <span class="ticker-score" style="color:${s.color}">${c.cvss != null ? c.cvss.toFixed(1) : ''}</span>
      </span>`;
    }).join('');

    // Two identical halves → translateX(-50%) loops seamlessly.
    track.innerHTML = html + html;
    track.style.setProperty('--ticker-dur', `${Math.max(28, items.length * 4)}s`);
    track.addEventListener('click', (e) => {
      if (e.target.closest('.ticker-item') && typeof navigateTo === 'function') navigateTo('cve');
    });
    wrap.style.display = 'flex';
  }

  document.addEventListener('DOMContentLoaded', load);
})();
