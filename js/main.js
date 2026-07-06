const pageTitles = {
  dashboard:  { title: 'SOC Dashboard',      sub: 'SentinelX · Real-time Monitoring' },
  logs:       { title: 'Log Analyzer',       sub: 'Raw parsing / Pattern matching' },
  ips:        { title: 'IP Lookup',          sub: 'Geo / ASN / Threat intel' },
  dns:        { title: 'DNS Lookup',         sub: 'Records / Domain intelligence' },
  blocklist:  { title: 'Blocklist Manager',  sub: 'Per-account IP blocklist' },
  hash:       { title: 'Hash Generator',     sub: 'Crypto / Verification' },
  password:   { title: 'Password Checker',   sub: 'Strength / Breach detection' },
  cve:        { title: 'CVE Live Feed',      sub: 'NVD / Real-time vulnerabilities' },
  ssl:        { title: 'SSL / TLS Inspector',sub: 'crt.sh / Certificate Transparency' },
  email:      { title: 'Email Security',     sub: 'SPF / DMARC / DKIM / DNSSEC' },
  abuseipdb:  { title: 'AbuseIPDB',          sub: 'IP Reputation / Threat intelligence' },
  typosquat:  { title: 'Typosquat Scanner',  sub: 'Phishing / Look-alike domains' },
  settings:   { title: 'Settings',           sub: 'Preferences / Data management' }
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

  // Keep the URL in sync so a reload (or shared link) reopens the same page
  history.replaceState(null, '', pageId === 'dashboard' ? location.pathname : '#' + pageId);

  if (pageId === 'blocklist' && typeof renderBlocklist === 'function') renderBlocklist();
}

// Deep-link: open the page named in the URL hash (e.g. app.html#hash)
document.addEventListener('DOMContentLoaded', () => {
  const initial = location.hash.replace('#', '');
  if (initial && pageTitles[initial]) navigateTo(initial);
});

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

// ── Rail tooltips: labels are hidden in the icon rail, so lift each
//    item's label text into data-tip for the CSS hover tooltip.
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.sidebar .nav-item').forEach((el) => {
    const label = el.querySelector('.nav-label')?.textContent?.trim();
    if (label) el.setAttribute('data-tip', label);
  });
  document.getElementById('account-signin')?.setAttribute('data-tip', 'Sign in to sync');
});

// ── Theme Management ───────────────────────────────
const html = document.documentElement;
const themeToggle = document.getElementById('theme-toggle');
const settingsTheme = document.getElementById('settings-theme');

// Icon shows the theme you'd switch to: sun while dark, moon while light.
const THEME_ICONS = {
  dark: '<svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>',
  light: '<svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>',
};

function setTheme(theme) {
  html.setAttribute('data-theme', theme);
  localStorage.setItem('nsd_theme', theme);
  if (themeToggle) themeToggle.innerHTML = THEME_ICONS[theme] || THEME_ICONS.dark;
  if (settingsTheme) settingsTheme.checked = theme === 'light';
}

document.addEventListener('DOMContentLoaded', () => {
  const saved = localStorage.getItem('nsd_theme') || 'dark';
  html.setAttribute('data-theme', saved);
  if (themeToggle) themeToggle.innerHTML = THEME_ICONS[saved] || THEME_ICONS.dark;
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

// ── Keyboard Shortcuts ─────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const modal = document.getElementById('shortcuts-modal');
  const close = document.getElementById('shortcuts-close');

  window.toggleShortcutsModal = () => {
    modal?.classList.toggle('modal-open');
  };

  close?.addEventListener('click', toggleShortcutsModal);
  modal?.addEventListener('click', e => {
    if (e.target === modal) toggleShortcutsModal();
  });

  document.addEventListener('keydown', (e) => {
    // Ignore if user is typing in an input
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
      if (e.key === 'Escape') e.target.blur();
      return;
    }

    if (e.key === '?') { e.preventDefault(); toggleShortcutsModal(); }
    if (e.key.toLowerCase() === 't') { e.preventDefault(); themeToggle?.click(); }
    if (e.key === 'Escape' && modal?.classList.contains('modal-open')) toggleShortcutsModal();

    const keys = { '1': 'dashboard', '2': 'logs', '3': 'ips', '4': 'dns', '5': 'blocklist', '6': 'hash', '7': 'password', '8': 'cve', '9': 'ssl', '0': 'abuseipdb' };
    if (keys[e.key]) {
      e.preventDefault();
      navigateTo(keys[e.key]);
    }
  });
});

// ── Dashboard → Blocklist shortcut ─────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('dash-view-blocklist')?.addEventListener('click', () => navigateTo('blocklist'));

  // Quick Launch tiles (and any element with data-goto) navigate like the sidebar
  document.querySelectorAll('[data-goto]').forEach(el => {
    el.addEventListener('click', () => navigateTo(el.dataset.goto));
  });
});

// ── Animated count-up for stat values ───────────────
window.animateNumber = function (el, to, ms = 500) {
  if (!el) return;
  const from = parseInt(String(el.textContent).replace(/[^\d-]/g, ''), 10) || 0;
  if (from === to) { el.textContent = to.toLocaleString(); return; }
  const start = performance.now();
  (function tick(t) {
    const p = Math.min(1, (t - start) / ms);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(from + (to - from) * eased).toLocaleString();
    if (p < 1) requestAnimationFrame(tick);
  })(start);
};

// ── Pointer-tracked micro-interactions ──────────────
//    * stat cards tilt in 3D toward the cursor
//    * primary buttons are gently "magnetic"
if (!matchMedia('(prefers-reduced-motion: reduce)').matches) {
  document.addEventListener('pointermove', (e) => {
    const card = e.target.closest?.('.kpi-card');
    if (card) {
      const r = card.getBoundingClientRect();
      const rx = ((e.clientY - r.top) / r.height - 0.5) * -5;
      const ry = ((e.clientX - r.left) / r.width - 0.5) * 6;
      card.style.transform = `perspective(600px) translateY(-3px) rotateX(${rx.toFixed(2)}deg) rotateY(${ry.toFixed(2)}deg)`;
      return;
    }
    const btn = e.target.closest?.('.analyze-btn');
    if (btn && !btn.disabled) {
      const r = btn.getBoundingClientRect();
      const dx = ((e.clientX - r.left) / r.width - 0.5) * 6;
      const dy = ((e.clientY - r.top) / r.height - 0.5) * 4;
      btn.style.transform = `translate(${dx.toFixed(1)}px, ${(dy - 1).toFixed(1)}px)`;
    }
  });
  document.addEventListener('pointerout', (e) => {
    const el = e.target.closest?.('.kpi-card, .analyze-btn');
    if (el && !el.contains(e.relatedTarget)) el.style.transform = '';
  });
}

// ── Settings Page Logic ────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('settings-version')?.replaceChildren('2.1.0');

  // Route through clearBlocklist() so server-side entries are removed too when signed in.
  document.getElementById('settings-clear-blocklist')?.addEventListener('click', () => {
    if (typeof clearBlocklist === 'function') clearBlocklist();
  });

  document.getElementById('settings-clear-data')?.addEventListener('click', () => {
    if (confirm('Are you sure you want to delete all local data? This cannot be undone.')) {
      localStorage.clear();
      location.reload();
    }
  });
});