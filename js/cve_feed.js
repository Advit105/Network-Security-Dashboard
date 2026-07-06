// ── CVE Live Feed — NVD API v2.0 ─────────────────────
// Fetches latest CVEs from the National Vulnerability Database
// No API key required, free and public
// ──────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  const feedContainer = document.getElementById('cve-feed-list');
  const refreshBtn    = document.getElementById('cve-refresh-btn');
  const filterSelect  = document.getElementById('cve-severity-filter');
  const loadingEl     = document.getElementById('cve-loading');
  const errorEl       = document.getElementById('cve-error');
  const countBadge    = document.getElementById('cve-count');
  const lastUpdated   = document.getElementById('cve-last-updated');
  const searchInput   = document.getElementById('cve-search');

  if (!feedContainer) return;

  let allCves = [];
  let autoRefreshTimer = null;

  // CVSS severity color mapping
  function getSeverityInfo(score) {
    if (score === null || score === undefined) return { label: 'N/A', cls: 'na', color: 'var(--text-3)' };
    if (score >= 9.0) return { label: 'CRITICAL', cls: 'critical', color: 'var(--red)' };
    if (score >= 7.0) return { label: 'HIGH',     cls: 'high',     color: 'var(--amber)' };
    if (score >= 4.0) return { label: 'MEDIUM',   cls: 'medium',   color: 'var(--cyan)' };
    return { label: 'LOW', cls: 'low', color: 'var(--green)' };
  }

  function formatDate(dateStr) {
    const d = new Date(dateStr);
    const now = new Date();
    const diffMs = now - d;
    const diffH = Math.floor(diffMs / 3600000);
    const diffM = Math.floor(diffMs / 60000);

    if (diffM < 60) return `${diffM}m ago`;
    if (diffH < 24) return `${diffH}h ago`;
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }

  function extractCVSS(vuln) {
    // Try CVSS v3.1 first, then v3.0, then v2.0
    const metrics = vuln.cve?.metrics;
    if (!metrics) return null;

    if (metrics.cvssMetricV31?.length > 0) return metrics.cvssMetricV31[0].cvssData?.baseScore;
    if (metrics.cvssMetricV30?.length > 0) return metrics.cvssMetricV30[0].cvssData?.baseScore;
    if (metrics.cvssMetricV2?.length > 0)  return metrics.cvssMetricV2[0].cvssData?.baseScore;
    return null;
  }

  function extractVector(vuln) {
    const metrics = vuln.cve?.metrics;
    if (!metrics) return '';
    if (metrics.cvssMetricV31?.length > 0) return metrics.cvssMetricV31[0].cvssData?.vectorString || '';
    if (metrics.cvssMetricV30?.length > 0) return metrics.cvssMetricV30[0].cvssData?.vectorString || '';
    return '';
  }

  function truncateDesc(desc, max = 180) {
    if (!desc || desc.length <= max) return desc || 'No description available.';
    return desc.substring(0, max).trim() + '…';
  }

  async function fetchCVEs() {
    loadingEl.style.display = 'flex';
    errorEl.style.display = 'none';
    feedContainer.innerHTML = '';

    try {
      // Fetch last 20 published CVEs from the last 7 days
      const now = new Date();
      const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const pubStart = weekAgo.toISOString().split('.')[0] + '.000';
      const pubEnd   = now.toISOString().split('.')[0] + '.000';

      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${pubStart}&pubEndDate=${pubEnd}&resultsPerPage=20`;

      const res = await fetch(url);
      if (!res.ok) throw new Error(`NVD API returned ${res.status}`);

      const data = await res.json();
      allCves = (data.vulnerabilities || []).map(v => {
        const cve = v.cve;
        const cvss = extractCVSS(v);
        const severity = getSeverityInfo(cvss);
        const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
        const vector = extractVector(v);
        const refs = cve.references?.slice(0, 3) || [];
        const products = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.slice(0, 3)?.map(c => {
          const parts = c.criteria?.split(':');
          return parts?.length > 4 ? `${parts[3]} ${parts[4]}` : c.criteria;
        }) || [];

        return {
          id: cve.id,
          desc,
          cvss,
          severity,
          vector,
          published: cve.published,
          modified: cve.lastModified,
          refs,
          products
        };
      });

      // Sort by CVSS score descending (critical first)
      allCves.sort((a, b) => (b.cvss || 0) - (a.cvss || 0));

      renderCVEs();
      if (lastUpdated) lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    } catch (err) {
      console.error('CVE fetch error:', err);
      errorEl.style.display = 'block';
      document.getElementById('cve-error-msg').textContent = `Failed to fetch CVEs: ${err.message}. The NVD API may be rate-limited — try again in 30s.`;
    } finally {
      loadingEl.style.display = 'none';
    }
  }

  function renderCVEs() {
    const filter = filterSelect?.value || 'all';
    const search = (searchInput?.value || '').toLowerCase().trim();

    let filtered = allCves;

    if (filter !== 'all') {
      filtered = filtered.filter(c => c.severity.cls === filter);
    }
    if (search) {
      filtered = filtered.filter(c =>
        c.id.toLowerCase().includes(search) ||
        c.desc.toLowerCase().includes(search)
      );
    }

    if (countBadge) countBadge.textContent = `${filtered.length} CVEs`;

    if (filtered.length === 0) {
      feedContainer.innerHTML = '<div style="color:var(--text-3);text-align:center;padding:20px;font-size:12.5px">No CVEs match your filters.</div>';
      return;
    }

    feedContainer.innerHTML = filtered.map((c, i) => `
      <div class="cve-item" style="animation-delay:${i * 0.03}s" onclick="this.querySelector('.cve-details').classList.toggle('cve-open')">
        <div class="cve-top">
          <span class="feed-sev ${c.severity.cls}">${c.severity.label}</span>
          <div class="cve-id-row">
            <span class="cve-id-text">${c.id}</span>
            <span class="cve-score" style="color:${c.severity.color}">${c.cvss !== null ? c.cvss.toFixed(1) : '—'}</span>
          </div>
          <span class="feed-time">${formatDate(c.published)}</span>
        </div>
        <div class="cve-desc">${truncateDesc(c.desc)}</div>
        <div class="cve-details">
          ${c.vector ? `<div class="cve-vector"><span class="cve-detail-label">Vector:</span> <code>${c.vector}</code></div>` : ''}
          ${c.products.length ? `<div class="cve-products"><span class="cve-detail-label">Affected:</span> ${c.products.join(', ')}</div>` : ''}
          ${c.refs.length ? `<div class="cve-refs">${c.refs.map(r => `<a href="${r.url}" target="_blank" rel="noopener" class="cve-ref-link">${r.source || 'Reference'}</a>`).join(' ')}</div>` : ''}
        </div>
      </div>
    `).join('');
  }

  // Event listeners
  refreshBtn?.addEventListener('click', fetchCVEs);
  filterSelect?.addEventListener('change', renderCVEs);
  searchInput?.addEventListener('input', renderCVEs);

  // Auto-refresh every 5 minutes
  function startAutoRefresh() {
    if (autoRefreshTimer) clearInterval(autoRefreshTimer);
    autoRefreshTimer = setInterval(fetchCVEs, 5 * 60 * 1000);
  }

  // Initial load
  fetchCVEs();
  startAutoRefresh();
});
