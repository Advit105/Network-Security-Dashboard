// ── Page Titles ────────────────────────────────────
const pageTitles = {
  dashboard: { title: 'Dashboard',         sub: 'Overview / Real-time' },
  charts:    { title: 'Network Charts',    sub: 'Traffic / Threat Analysis' },
  logs:      { title: 'Log Analyzer',      sub: 'Raw parsing / Pattern matching' },
  ports:     { title: 'Port Scanner',      sub: 'Live scanning / Mapping' },
  ips:       { title: 'IP Lookup',         sub: 'Geo / ASN / Threat intel' },
  blocklist: { title: 'Blocklist Manager', sub: 'Local firewall simulation' },
  hash:      { title: 'Hash Generator',    sub: 'Crypto / Verification' },
  password:  { title: 'Password Checker',  sub: 'Strength / Crack time estimation' },
  settings:  { title: 'Settings',          sub: 'Preferences / Data management' }
};

// ── Navigation (SPA) ───────────────────────────────
function navigateTo(pageId) {
  // Update nav active state
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === pageId);
  });

  // Show active page
  document.querySelectorAll('.page').forEach(el => {
    el.classList.toggle('active', el.id === 'page-' + pageId);
  });

  // Update topbar title
  const info = pageTitles[pageId];
  if (info) {
    document.getElementById('page-title').textContent = info.title;
    document.getElementById('page-sub').textContent   = info.sub;
  }

  // Close mobile sidebar
  document.querySelector('.sidebar')?.classList.remove('sidebar-open');

  if (pageId === 'charts'    && typeof initCharts     === 'function') initCharts();
  if (pageId === 'blocklist' && typeof renderBlocklist === 'function') renderBlocklist();
}

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', e => {
    e.preventDefault();
    navigateTo(item.dataset.page);
  });
});

// ── Hamburger Menu ─────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const hamburger = document.getElementById('hamburger');
  const sidebar   = document.querySelector('.sidebar');
  if (hamburger && sidebar) {
    hamburger.addEventListener('click', () => {
      sidebar.classList.toggle('sidebar-open');
    });
  }
});

// ── Theme Management ───────────────────────────────
const html = document.documentElement;
const themeToggle = document.getElementById('theme-toggle');
const settingsTheme = document.getElementById('settings-theme');

function setTheme(theme) {
  html.setAttribute('data-theme', theme);
  localStorage.setItem('nsd_theme', theme);
  if (themeToggle) themeToggle.textContent = theme === 'dark' ? '☀ Light' : '☾ Dark';
  if (settingsTheme) settingsTheme.checked = theme === 'light';
  if (typeof showToast === 'function') showToast(`Switched to ${theme} mode`, 'info');
}

document.addEventListener('DOMContentLoaded', () => {
  const saved = localStorage.getItem('nsd_theme') || 'dark';
  html.setAttribute('data-theme', saved);
  if (themeToggle) themeToggle.textContent = saved === 'dark' ? '☀ Light' : '☾ Dark';
  if (settingsTheme) settingsTheme.checked = saved === 'light';

  themeToggle?.addEventListener('click', () => {
    const current = html.getAttribute('data-theme');
    setTheme(current === 'dark' ? 'light' : 'dark');
  });

  settingsTheme?.addEventListener('change', (e) => {
    setTheme(e.target.checked ? 'light' : 'dark');
  });
});

// ── Live Clock ─────────────────────────────────────
function updateClock() {
  const clock = document.getElementById('clock');
  if (!clock) return;
  const now = new Date();
  const h = String(now.getHours()).padStart(2, '0');
  const m = String(now.getMinutes()).padStart(2, '0');
  const s = String(now.getSeconds()).padStart(2, '0');
  clock.textContent = `${h}:${m}:${s}`;
}
setInterval(updateClock, 1000);
document.addEventListener('DOMContentLoaded', updateClock);

// ── Keyboard Shortcuts ─────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const modal = document.getElementById('shortcuts-modal');
  const close = document.getElementById('shortcuts-close');

  window.toggleShortcutsModal = () => {
    if (modal) modal.style.display = modal.style.display === 'flex' ? 'none' : 'flex';
  };

  close?.addEventListener('click', toggleShortcutsModal);
  modal?.addEventListener('click', e => {
    if (e.target === modal) toggleShortcutsModal();
  });

  document.addEventListener('keydown', (e) => {
    // Ignore if user is typing in an input
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
      if (e.key === 'Escape') {
        e.target.blur();
        const search = document.getElementById('global-search');
        if (search) search.value = '';
        const results = document.getElementById('search-results');
        if (results) results.style.display = 'none';
      }
      return;
    }

    if (e.key === '?') { e.preventDefault(); toggleShortcutsModal(); }
    if (e.key.toLowerCase() === 't') { e.preventDefault(); themeToggle?.click(); }
    if (e.key === 'Escape' && modal?.style.display === 'flex') toggleShortcutsModal();

    // Map 1-9 to navigation pages
    const keys = { '1': 'dashboard', '2': 'charts', '3': 'logs', '4': 'ports', '5': 'ips', '6': 'blocklist', '7': 'hash', '8': 'password', '9': 'settings' };
    if (keys[e.key]) {
      e.preventDefault();
      navigateTo(keys[e.key]);
      if (typeof showToast === 'function') {
        showToast(`Navigated to ${pageTitles[keys[e.key]].title}`);
      }
    }
  });
});

// ── Global Search ──────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const searchInput = document.getElementById('global-search');
  const searchResults = document.getElementById('search-results');
  if (!searchInput || !searchResults) return;

  const searchablePages = Object.keys(pageTitles).map(k => ({
    id: k,
    title: pageTitles[k].title,
    sub: pageTitles[k].sub
  }));

  searchInput.addEventListener('input', () => {
    const q = searchInput.value.toLowerCase().trim();
    if (!q) {
      searchResults.style.display = 'none';
      return;
    }

    const matches = searchablePages.filter(p => 
      p.title.toLowerCase().includes(q) || p.sub.toLowerCase().includes(q)
    );

    if (matches.length > 0) {
      searchResults.innerHTML = matches.map(m => `
        <div class="search-result-item" onclick="navigateTo('${m.id}'); document.getElementById('global-search').value=''; this.parentElement.style.display='none'">
          <strong>${m.title}</strong><br>
          <small>${m.sub}</small>
        </div>
      `).join('');
      searchResults.style.display = 'flex';
    } else {
      searchResults.innerHTML = `<div class="search-result-item">No pages found</div>`;
      searchResults.style.display = 'flex';
    }
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('.search-wrap')) {
      searchResults.style.display = 'none';
    }
  });
});

// ── Live Metrics Simulation ────────────────────────
let threats = 42;
let ports = 7;
let uptime = 0;

function simulateLiveMetrics() {
  uptime += 3;
  const elUptime = document.getElementById('counter-uptime');
  if (elUptime) {
    const h = Math.floor(uptime / 3600);
    const m = Math.floor((uptime % 3600) / 60);
    const s = uptime % 60;
    elUptime.textContent = `${h}h ${m}m ${s}s`;
  }

  if (Math.random() > 0.7) {
    threats += Math.floor(Math.random() * 3);
    const elThreats = document.getElementById('counter-threats');
    if (elThreats) {
      elThreats.textContent = threats;
      elThreats.classList.add('flash');
      setTimeout(() => elThreats.classList.remove('flash'), 300);
    }
  }

  if (Math.random() > 0.9) {
    ports += 1;
    const elPorts = document.getElementById('counter-ports');
    if (elPorts) {
      elPorts.textContent = ports;
      elPorts.classList.add('flash-warn');
      setTimeout(() => elPorts.classList.remove('flash-warn'), 300);
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  setInterval(simulateLiveMetrics, 3000);
});

// ── Export Report ──────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const exportBtn = document.getElementById('export-report-btn');
  if (!exportBtn) return;

  exportBtn.addEventListener('click', () => {
    const reportData = `SentinelX Security Report
Generated: ${new Date().toLocaleString()}

Metrics:
- Threats: ${document.getElementById('counter-threats')?.textContent || 0}
- Open Ports: ${document.getElementById('counter-ports')?.textContent || 0}
- Blocked IPs: ${document.getElementById('blocked-metric-val')?.textContent || 0}

This report was auto-generated by the SentinelX dashboard.`;

    const blob = new Blob([reportData], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinelx-report-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    if (typeof showToast === 'function') showToast('Report exported successfully', 'success');
  });
});

// ── Settings Page Logic ────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('settings-version')?.replaceChildren('1.5.0 (Phase 5)');
  
  document.getElementById('settings-clear-blocklist')?.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear the blocklist?')) {
      localStorage.removeItem('nsd_blocklist');
      if (typeof renderBlocklist === 'function') renderBlocklist();
      if (typeof showToast === 'function') showToast('Blocklist cleared', 'warn');
    }
  });

  document.getElementById('settings-clear-data')?.addEventListener('click', () => {
    if (confirm('Are you sure you want to delete all local data? This cannot be undone.')) {
      localStorage.clear();
      location.reload();
    }
  });
});