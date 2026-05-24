// ── SSL/TLS Certificate Inspector — crt.sh API ──────
// Queries Certificate Transparency logs for any domain
// Shows issued certs, CA, validity, and subdomains
// No API key required — uses crt.sh public API
// ─────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  const domainInput  = document.getElementById('ssl-domain-input');
  const lookupBtn    = document.getElementById('ssl-lookup-btn');
  const loadingEl    = document.getElementById('ssl-loading');
  const errorEl      = document.getElementById('ssl-error');
  const resultsPanel = document.getElementById('ssl-results-panel');
  const summaryEl    = document.getElementById('ssl-summary');
  const certsBody    = document.getElementById('ssl-certs-tbody');
  const subdomainsList = document.getElementById('ssl-subdomains-list');
  const subdomainsPanel = document.getElementById('ssl-subdomains-panel');
  const subdomainCount  = document.getElementById('ssl-subdomain-count');
  const statsPanel      = document.getElementById('ssl-stats-panel');

  if (!domainInput) return;

  // Quick domain buttons
  document.querySelectorAll('.quick-ssl-domain').forEach(btn => {
    btn.addEventListener('click', () => {
      domainInput.value = btn.dataset.domain;
      lookupSSL();
    });
  });

  function formatCertDate(dateStr) {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }

  function isExpired(dateStr) {
    if (!dateStr) return false;
    return new Date(dateStr) < new Date();
  }

  function daysUntilExpiry(dateStr) {
    if (!dateStr) return null;
    const diff = new Date(dateStr) - new Date();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  }

  function getExpiryBadge(notAfter) {
    const days = daysUntilExpiry(notAfter);
    if (days === null) return '<span class="feed-sev medium">Unknown</span>';
    if (days < 0) return '<span class="feed-sev critical">Expired</span>';
    if (days < 30) return `<span class="feed-sev critical">${days}d left</span>`;
    if (days < 90) return `<span class="feed-sev high">${days}d left</span>`;
    return `<span class="feed-sev low">${days}d left</span>`;
  }

  async function lookupSSL() {
    const domain = domainInput.value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!domain) {
      if (typeof showToast === 'function') showToast('Please enter a domain name', 'warn');
      return;
    }

    loadingEl.style.display = 'flex';
    errorEl.style.display = 'none';
    resultsPanel.style.display = 'none';
    subdomainsPanel.style.display = 'none';
    statsPanel.style.display = 'none';

    try {
      const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`);
      if (!res.ok) throw new Error(`crt.sh returned ${res.status}`);

      const data = await res.json();

      if (!data || data.length === 0) {
        throw new Error(`No certificates found for "${domain}"`);
      }

      // Process and deduplicate certs
      const seen = new Set();
      const certs = [];
      const subdomains = new Set();

      for (const entry of data) {
        // Collect subdomains from name_value
        if (entry.name_value) {
          entry.name_value.split('\n').forEach(name => {
            const clean = name.trim().toLowerCase().replace(/^\*\./, '');
            if (clean && clean !== domain.toLowerCase()) {
              subdomains.add(clean);
            }
          });
        }

        // Deduplicate by serial number
        const key = entry.serial_number || `${entry.id}`;
        if (seen.has(key)) continue;
        seen.add(key);

        certs.push({
          id: entry.id,
          commonName: entry.common_name || '—',
          nameValue: entry.name_value || '',
          issuer: entry.issuer_name || '—',
          issuerCA: extractCA(entry.issuer_name),
          notBefore: entry.not_before,
          notAfter: entry.not_after,
          serialNumber: entry.serial_number || '—',
          expired: isExpired(entry.not_after),
          loggedAt: entry.entry_timestamp
        });
      }

      // Sort by not_before desc (newest first)
      certs.sort((a, b) => new Date(b.notBefore) - new Date(a.notBefore));

      // Take top 25 for display
      const displayCerts = certs.slice(0, 25);

      // Stats
      const totalCerts = certs.length;
      const activeCerts = certs.filter(c => !c.expired).length;
      const expiredCerts = totalCerts - activeCerts;
      const uniqueIssuers = new Set(certs.map(c => c.issuerCA)).size;
      const wildcardCerts = certs.filter(c => c.commonName.startsWith('*.')).length;

      // Render stats
      renderStats(totalCerts, activeCerts, expiredCerts, uniqueIssuers, wildcardCerts);

      // Render certs table
      renderCerts(displayCerts, totalCerts);

      // Render subdomains
      renderSubdomains([...subdomains].sort(), domain);

      summaryEl.innerHTML = `
        <span class="alert-badge info">${totalCerts} certificates</span>
        <span class="alert-badge success">${activeCerts} active</span>
        ${expiredCerts > 0 ? `<span class="alert-badge danger">${expiredCerts} expired</span>` : ''}
      `;

      resultsPanel.style.display = 'flex';
      if (typeof showToast === 'function') showToast(`Found ${totalCerts} certificates for ${domain}`, 'success');

    } catch (err) {
      console.error('SSL lookup error:', err);
      errorEl.style.display = 'block';
      document.getElementById('ssl-error-msg').textContent = err.message;
    } finally {
      loadingEl.style.display = 'none';
    }
  }

  function extractCA(issuerStr) {
    if (!issuerStr) return 'Unknown';
    // Extract O= (Organization) from the issuer DN
    const match = issuerStr.match(/O=([^,]+)/);
    return match ? match[1].trim() : issuerStr.substring(0, 40);
  }

  function renderStats(total, active, expired, issuers, wildcards) {
    statsPanel.style.display = 'grid';
    document.getElementById('ssl-stat-total').textContent = total;
    document.getElementById('ssl-stat-active').textContent = active;
    document.getElementById('ssl-stat-expired').textContent = expired;
    document.getElementById('ssl-stat-issuers').textContent = issuers;
  }

  function renderCerts(certs, total) {
    certsBody.innerHTML = certs.map(c => `
      <tr class="${c.expired ? 'cert-expired' : ''}">
        <td><span class="mono">${c.commonName}</span></td>
        <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${c.issuerCA}">${c.issuerCA}</td>
        <td><span class="mono">${formatCertDate(c.notBefore)}</span></td>
        <td>${getExpiryBadge(c.notAfter)}</td>
        <td><span class="mono" style="font-size:10px;opacity:0.6">${c.serialNumber.substring(0, 16)}…</span></td>
      </tr>
    `).join('');

    if (total > 25) {
      certsBody.innerHTML += `<tr><td colspan="5" style="text-align:center;color:var(--text-3);padding:12px">Showing 25 of ${total} certificates</td></tr>`;
    }
  }

  function renderSubdomains(subdomains, domain) {
    if (subdomains.length === 0) {
      subdomainsPanel.style.display = 'none';
      return;
    }

    subdomainsPanel.style.display = 'flex';
    subdomainCount.textContent = `${subdomains.length} found`;

    subdomainsList.innerHTML = subdomains.slice(0, 40).map(s => `
      <span class="subdomain-tag">${s}</span>
    `).join('');

    if (subdomains.length > 40) {
      subdomainsList.innerHTML += `<span class="subdomain-tag" style="color:var(--text-3)">+${subdomains.length - 40} more</span>`;
    }
  }

  // Event listeners
  lookupBtn?.addEventListener('click', lookupSSL);
  domainInput?.addEventListener('keydown', e => {
    if (e.key === 'Enter') lookupSSL();
  });
});
