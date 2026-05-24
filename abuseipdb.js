// ── AbuseIPDB IP Reputation Checker ──────────────────
// Checks IP threat reputation via AbuseIPDB API
// Requires a free API key from https://www.abuseipdb.com
// Key is stored in localStorage for persistence
// ─────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  const ipInput      = document.getElementById('abuse-ip-input');
  const checkBtn     = document.getElementById('abuse-check-btn');
  const loadingEl    = document.getElementById('abuse-loading');
  const errorEl      = document.getElementById('abuse-error');
  const resultsPanel = document.getElementById('abuse-results-panel');
  const apiKeyInput  = document.getElementById('abuse-apikey');
  const saveKeyBtn   = document.getElementById('abuse-save-key');
  const keyStatus    = document.getElementById('abuse-key-status');

  if (!ipInput) return;

  const STORAGE_KEY = 'sentinelx_abuseipdb_key';

  // Load saved API key
  function loadKey() {
    const saved = localStorage.getItem(STORAGE_KEY) || '';
    if (apiKeyInput) apiKeyInput.value = saved;
    updateKeyStatus(saved);
    return saved;
  }

  function updateKeyStatus(key) {
    if (!keyStatus) return;
    if (key && key.length > 10) {
      keyStatus.innerHTML = '<span style="color:var(--green)">✓ Key configured</span>';
    } else {
      keyStatus.innerHTML = '<span style="color:var(--text-3)">No key set</span>';
    }
  }

  function saveKey() {
    const key = apiKeyInput?.value.trim() || '';
    localStorage.setItem(STORAGE_KEY, key);
    updateKeyStatus(key);
    if (typeof showToast === 'function') {
      showToast(key ? 'API key saved' : 'API key cleared', key ? 'success' : 'warn');
    }
  }

  // Quick IP buttons
  document.querySelectorAll('.quick-abuse-ip').forEach(btn => {
    btn.addEventListener('click', () => {
      ipInput.value = btn.dataset.ip;
      checkIP();
    });
  });

  function getConfidenceBadge(score) {
    if (score >= 80) return { label: 'MALICIOUS',  cls: 'critical', color: 'var(--red)' };
    if (score >= 50) return { label: 'SUSPICIOUS', cls: 'high',     color: 'var(--amber)' };
    if (score >= 20) return { label: 'LOW RISK',   cls: 'medium',   color: 'var(--cyan)' };
    if (score > 0)   return { label: 'MINIMAL',    cls: 'low',      color: 'var(--green)' };
    return { label: 'CLEAN', cls: 'low', color: 'var(--green)' };
  }

  function getCategoryName(catId) {
    const cats = {
      1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
      5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
      9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
      13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
      17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
      21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted'
    };
    return cats[catId] || `Category ${catId}`;
  }

  async function checkIP() {
    const ip = ipInput.value.trim();
    if (!ip) {
      if (typeof showToast === 'function') showToast('Please enter an IP address', 'warn');
      return;
    }

    const apiKey = localStorage.getItem(STORAGE_KEY) || '';
    if (!apiKey) {
      if (typeof showToast === 'function') showToast('Please set your AbuseIPDB API key first', 'warn');
      apiKeyInput?.focus();
      return;
    }

    loadingEl.style.display = 'flex';
    errorEl.style.display = 'none';
    resultsPanel.style.display = 'none';

    try {
      const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;

      const res = await fetch(url, {
        headers: {
          'Key': apiKey,
          'Accept': 'application/json'
        }
      });

      if (res.status === 401 || res.status === 403) {
        throw new Error('Invalid API key. Get a free key at abuseipdb.com');
      }
      if (res.status === 429) {
        throw new Error('Rate limit exceeded. Free tier allows 1000 checks/day.');
      }
      if (!res.ok) throw new Error(`AbuseIPDB returned ${res.status}`);

      const json = await res.json();
      const d = json.data;

      if (!d) throw new Error('No data returned for this IP');

      const badge = getConfidenceBadge(d.abuseConfidenceScore);

      // Render results
      renderResults(d, badge);
      resultsPanel.style.display = 'block';

      if (typeof showToast === 'function') {
        showToast(`${ip}: ${badge.label} (${d.abuseConfidenceScore}% confidence)`, badge.cls === 'critical' ? 'danger' : badge.cls === 'high' ? 'warn' : 'success');
      }

    } catch (err) {
      console.error('AbuseIPDB error:', err);
      errorEl.style.display = 'block';
      document.getElementById('abuse-error-msg').textContent = err.message;
    } finally {
      loadingEl.style.display = 'none';
    }
  }

  function renderResults(d, badge) {
    // Score gauge
    const scoreEl = document.getElementById('abuse-score');
    const scoreLabelEl = document.getElementById('abuse-score-label');
    const scoreBarEl = document.getElementById('abuse-score-bar');
    const ipDisplay = document.getElementById('abuse-ip-display');
    const ispEl = document.getElementById('abuse-isp');
    const countryEl = document.getElementById('abuse-country');
    const usageEl = document.getElementById('abuse-usage');
    const domainEl = document.getElementById('abuse-domain');
    const reportsEl = document.getElementById('abuse-total-reports');
    const distinctEl = document.getElementById('abuse-distinct-users');
    const lastReportEl = document.getElementById('abuse-last-reported');
    const categoriesEl = document.getElementById('abuse-categories');
    const whitelistEl = document.getElementById('abuse-whitelist');

    if (scoreEl) scoreEl.textContent = d.abuseConfidenceScore + '%';
    if (scoreEl) scoreEl.style.color = badge.color;
    if (scoreLabelEl) {
      scoreLabelEl.textContent = badge.label;
      scoreLabelEl.style.color = badge.color;
    }
    if (scoreBarEl) {
      scoreBarEl.style.width = d.abuseConfidenceScore + '%';
      scoreBarEl.style.background = `linear-gradient(90deg, var(--green), ${badge.color})`;
    }

    if (ipDisplay) ipDisplay.textContent = d.ipAddress;
    if (ispEl) ispEl.textContent = d.isp || '—';
    if (countryEl) countryEl.textContent = (d.countryName || '—') + (d.countryCode ? ` (${d.countryCode})` : '');
    if (usageEl) usageEl.textContent = d.usageType || '—';
    if (domainEl) domainEl.textContent = d.domain || '—';
    if (reportsEl) reportsEl.textContent = (d.totalReports || 0).toLocaleString();
    if (distinctEl) distinctEl.textContent = (d.numDistinctUsers || 0).toLocaleString();
    if (lastReportEl) {
      lastReportEl.textContent = d.lastReportedAt
        ? new Date(d.lastReportedAt).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
        : 'Never';
    }
    if (whitelistEl) {
      whitelistEl.innerHTML = d.isWhitelisted
        ? '<span style="color:var(--green)">✓ Whitelisted</span>'
        : '<span style="color:var(--text-3)">✗ Not whitelisted</span>';
    }

    // Categories
    if (categoriesEl) {
      const cats = d.reports
        ? [...new Set(d.reports.flatMap(r => r.categories || []))]
        : [];

      if (cats.length > 0) {
        categoriesEl.innerHTML = cats.map(c =>
          `<span class="subdomain-tag" style="border-color:${badge.color}40;color:${badge.color}">${getCategoryName(c)}</span>`
        ).join('');
      } else {
        categoriesEl.innerHTML = '<span style="color:var(--text-3);font-size:12px">No attack categories reported</span>';
      }
    }

    // Recent reports
    const recentList = document.getElementById('abuse-recent-list');
    if (recentList && d.reports && d.reports.length > 0) {
      recentList.innerHTML = d.reports.slice(0, 8).map(r => `
        <div class="feed-item">
          <span class="feed-sev ${r.categories?.some(c => [14,15,16,18,22].includes(c)) ? 'critical' : 'high'}">
            ${r.categories?.length ? getCategoryName(r.categories[0]) : 'Unknown'}
          </span>
          <div class="feed-body">
            <div class="feed-title" style="font-size:11px;white-space:normal">${r.comment || 'No comment'}</div>
            <div class="feed-meta">Reporter: ${r.reporterCountryCode || '??'}</div>
          </div>
          <span class="feed-time">${new Date(r.reportedAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</span>
        </div>
      `).join('');
      document.getElementById('abuse-recent-panel').style.display = 'flex';
    } else if (recentList) {
      document.getElementById('abuse-recent-panel').style.display = 'none';
    }
  }

  // Event listeners
  checkBtn?.addEventListener('click', checkIP);
  saveKeyBtn?.addEventListener('click', saveKey);
  ipInput?.addEventListener('keydown', e => {
    if (e.key === 'Enter') checkIP();
  });

  // Load saved key on init
  loadKey();
});
