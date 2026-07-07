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
  ioc:        { title: 'IOC Extractor',      sub: 'Indicators / Refang / Pivot' },
  whois:      { title: 'WHOIS / RDAP',       sub: 'Domain age / Registration intel' },
  asn:        { title: 'ASN / Netblock',     sub: 'RIPEstat / Abuse contact' },
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

  // Update topbar title — in dark mode it decrypts into place
  const info = pageTitles[pageId];
  if (info) {
    const titleEl = document.getElementById('page-title');
    titleEl.textContent = info.title;
    document.getElementById('page-sub').textContent = info.sub;
    if (html.getAttribute('data-theme') === 'dark') window.decodeText?.(titleEl, 450);
  }

  // Close mobile sidebar
  document.querySelector('.sidebar')?.classList.remove('sidebar-open');

  // Keep the URL in sync so a reload (or shared link) reopens the same page
  history.replaceState(null, '', pageId === 'dashboard' ? location.pathname : '#' + pageId);

  if (pageId === 'blocklist' && typeof renderBlocklist === 'function') renderBlocklist();

  // Reveal any info tiles already in view on the freshly opened page
  requestAnimationFrame(() => window.checkTileReveals?.());
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

// Toggling plays a transition first: CRT power-on flicker into dark,
// clean white wipe into light. The attribute swap happens while the
// overlay is fully opaque, so the restyle itself is never visible.
function switchTheme(theme) {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) { setTheme(theme); return; }
  let fx = document.getElementById('theme-fx');
  if (!fx) {
    fx = document.createElement('div');
    fx.id = 'theme-fx';
    document.body.appendChild(fx);
  }
  fx.classList.remove('fx-dark', 'fx-light');
  void fx.offsetWidth; // restart the animation if spammed
  fx.classList.add(theme === 'dark' ? 'fx-dark' : 'fx-light');
  setTimeout(() => setTheme(theme), theme === 'dark' ? 300 : 180);
  fx.addEventListener('animationend', () => fx.classList.remove('fx-dark', 'fx-light'), { once: true });
}

document.addEventListener('DOMContentLoaded', () => {
  const saved = localStorage.getItem('nsd_theme') || 'dark';
  html.setAttribute('data-theme', saved);
  if (themeToggle) themeToggle.innerHTML = THEME_ICONS[saved] || THEME_ICONS.dark;
  if (settingsTheme) settingsTheme.checked = saved === 'light';

  themeToggle?.addEventListener('click', () => {
    const current = html.getAttribute('data-theme');
    switchTheme(current === 'dark' ? 'light' : 'dark');
  });

  settingsTheme?.addEventListener('change', (e) => {
    switchTheme(e.target.checked ? 'light' : 'dark');
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

// ── Pointer-tracked micro-interactions (dark mode only —
//    light mode is deliberately simple and static) ─────
//    * panels get a spotlight that follows the cursor
//    * stat cards tilt in 3D toward the cursor
//    * primary buttons are gently "magnetic"
//    * a phosphor glow trails the pointer across the console
if (!matchMedia('(prefers-reduced-motion: reduce)').matches) {
  let lastSpot = null;

  document.addEventListener('pointermove', (e) => {
    if (html.getAttribute('data-theme') !== 'dark') return;

    // Spotlight: expose cursor position to CSS as --sx/--sy
    const spot = e.target.closest?.('.panel, .map-panel, .kpi-card, .info-tile');
    if (lastSpot && lastSpot !== spot) {
      lastSpot.style.removeProperty('--sx');
      lastSpot.style.removeProperty('--sy');
    }
    lastSpot = spot;
    if (spot) {
      const r = spot.getBoundingClientRect();
      spot.style.setProperty('--sx', (e.clientX - r.left).toFixed(0) + 'px');
      spot.style.setProperty('--sy', (e.clientY - r.top).toFixed(0) + 'px');
    }

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

  // Trailing phosphor glow (CSS hides it in light mode)
  document.addEventListener('DOMContentLoaded', () => {
    const glow = document.createElement('div');
    glow.id = 'cursor-glow';
    document.body.appendChild(glow);
    let gx = innerWidth / 2, gy = innerHeight / 2, tx = gx, ty = gy;
    document.addEventListener('pointermove', (e) => { tx = e.clientX; ty = e.clientY; });
    (function trail() {
      gx += (tx - gx) * 0.12;
      gy += (ty - gy) * 0.12;
      glow.style.transform = `translate(${(gx - 260).toFixed(1)}px, ${(gy - 260).toFixed(1)}px)`;
      requestAnimationFrame(trail);
    })();
  });
}

// ── Scroll parallax ─────────────────────────────────
//    * the Kali watermark lags behind the page scroll (depth)
//    * info tiles below the fold reveal as they scroll into view
//      (position-checked, no IntersectionObserver — deterministic)
window.checkTileReveals = function () {
  document.querySelectorAll('.info-tile.reveal:not(.in)').forEach((el) => {
    const r = el.getBoundingClientRect();
    if (r.width && r.top < innerHeight * 0.95 && r.bottom > 0) el.classList.add('in');
  });
};

if (!matchMedia('(prefers-reduced-motion: reduce)').matches) {
  // .page elements scroll, and scroll doesn't bubble → capture phase
  document.addEventListener('scroll', (e) => {
    const page = e.target;
    if (!(page instanceof Element) || !page.classList?.contains('page')) return;
    const k = document.querySelector('.bg-kali');
    if (k) k.style.transform = `translateY(calc(-50% + ${(page.scrollTop * 0.08).toFixed(1)}px))`;
    checkTileReveals();
  }, { capture: true, passive: true });

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.info-tile').forEach((el, i) => {
      el.classList.add('reveal');
      el.style.animationDelay = (i % 3) * 90 + 'ms';
    });
    checkTileReveals();
  });
}

// ── Decode effect — text resolves out of random glyphs ──
window.decodeText = function (el, dur = 500) {
  if (!el || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const GLYPHS = '!<>-_\\/[]{}—=+*^?#$%&';
  const target = el.dataset.decodeTarget || el.textContent;
  el.dataset.decodeTarget = target;
  const t0 = performance.now();
  (function tick(t) {
    // Guard: if the text was swapped mid-animation (fast nav), stop
    if (el.dataset.decodeTarget !== target) return;
    const p = Math.min(1, (t - t0) / dur);
    const shown = Math.floor(p * target.length);
    let s = target.slice(0, shown);
    for (let i = shown; i < target.length; i++) {
      s += target[i] === ' ' ? ' ' : GLYPHS[(Math.random() * GLYPHS.length) | 0];
    }
    el.textContent = s;
    if (p < 1) requestAnimationFrame(tick);
    else delete el.dataset.decodeTarget;
  })(t0);
};

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