// ── Page Titles ────────────────────────────────────
const pageTitles = {
  dashboard: { title: 'Dashboard',         sub: 'Security Toolkit / Real-time' },
  logs:      { title: 'Log Analyzer',      sub: 'Raw parsing / Pattern matching' },
  ips:       { title: 'IP Lookup',         sub: 'Geo / ASN / Threat intel' },
  dns:       { title: 'DNS Lookup',        sub: 'Records / Domain intelligence' },
  blocklist: { title: 'Blocklist Manager', sub: 'Local firewall simulation' },
  hash:      { title: 'Hash Generator',    sub: 'Crypto / Verification' },
  password:  { title: 'Password Checker',  sub: 'Strength / Breach detection' },
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

// ── Session Uptime (real) ──────────────────────────
let sessionStart = Date.now();

function updateSessionUptime() {
  const el = document.getElementById('dash-uptime');
  if (!el) return;
  const elapsed = Math.floor((Date.now() - sessionStart) / 1000);
  const h = Math.floor(elapsed / 3600);
  const m = Math.floor((elapsed % 3600) / 60);
  const s = elapsed % 60;
  if (h > 0) {
    el.textContent = `${h}h ${m}m ${s}s`;
  } else if (m > 0) {
    el.textContent = `${m}m ${s}s`;
  } else {
    el.textContent = `${s}s`;
  }
}
setInterval(updateSessionUptime, 1000);
document.addEventListener('DOMContentLoaded', updateSessionUptime);

// ── Dashboard Blocked Count (real) ─────────────────
function updateDashBlockedCount() {
  const el = document.getElementById('dash-blocked-count');
  if (!el) return;
  try {
    const list = JSON.parse(localStorage.getItem('sentinelx_blocklist')) || [];
    el.textContent = list.length;
  } catch {
    el.textContent = '0';
  }
}
document.addEventListener('DOMContentLoaded', updateDashBlockedCount);
// Re-check every 2 seconds in case blocklist changes
setInterval(updateDashBlockedCount, 2000);

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

    // Map 1-8 to navigation pages (real pages only)
    const keys = { '1': 'dashboard', '2': 'logs', '3': 'ips', '4': 'dns', '5': 'blocklist', '6': 'hash', '7': 'password', '8': 'settings' };
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

// ── Export Report ──────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const exportBtn = document.getElementById('export-report-btn');
  if (!exportBtn) return;

  exportBtn.addEventListener('click', () => {
    let blockedCount = 0;
    try {
      blockedCount = (JSON.parse(localStorage.getItem('sentinelx_blocklist')) || []).length;
    } catch {}

    const reportData = `SentinelX Security Report
Generated: ${new Date().toLocaleString()}

Blocked IPs: ${blockedCount}

Available Tools:
- Log Analyzer (Real regex parsing)
- IP Lookup (Live ip-api.com)
- Blocklist Manager (Local storage)
- Hash Generator (Web Crypto API)
- Password Checker (Real entropy analysis)

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
  document.getElementById('settings-version')?.replaceChildren('2.0.0 (Real-time Only)');
  
  document.getElementById('settings-clear-blocklist')?.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear the blocklist?')) {
      localStorage.removeItem('sentinelx_blocklist');
      if (typeof renderBlocklist === 'function') renderBlocklist();
      updateDashBlockedCount();
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