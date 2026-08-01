// ═══════════════════════════════════════════════════
//  command_palette.js — ⌘K / Ctrl+K quick launcher
//  Fuzzy-jump to any page or run a quick action.
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  // Actions beyond navigation
  function buildCommands() {
    const nav = (typeof pageTitles === 'object')
      ? Object.keys(pageTitles).map(id => ({
          id, kind: 'page',
          title: pageTitles[id].title,
          sub: pageTitles[id].sub,
          run: () => navigateTo(id),
        }))
      : [];

    const actions = [
      { id: 'act-theme', kind: 'action', title: 'Toggle Theme', sub: 'Switch dark / light',
        run: () => document.getElementById('theme-toggle')?.click() },
      { id: 'act-export', kind: 'action', title: 'Export Blocklist', sub: 'Download your blocked IPs as .txt',
        run: () => { navigateTo('blocklist'); if (typeof downloadBlocklist === 'function') downloadBlocklist('txt'); } },
      { id: 'act-shortcuts', kind: 'action', title: 'Keyboard Shortcuts', sub: 'Show the shortcut cheatsheet',
        run: () => window.toggleShortcutsModal?.() },
      { id: 'act-myip', kind: 'action', title: 'Look Up My IP', sub: 'Detect and geolocate your address',
        run: () => { navigateTo('ips'); document.getElementById('myip-btn')?.click(); } },
    ];
    return [...nav, ...actions];
  }

  // Lightweight subsequence fuzzy score
  function score(query, text) {
    if (!query) return 1;
    const q = query.toLowerCase(), t = text.toLowerCase();
    if (t.includes(q)) return 100 - t.indexOf(q);
    // subsequence check
    let qi = 0;
    for (let i = 0; i < t.length; i++) { if (t[i] === q[qi]) qi++; if (qi === q.length) return 20; }
    return 0;
  }

  let overlay, input, list, commands = [], filtered = [], active = 0;

  function open() {
    commands = buildCommands();
    overlay.classList.add('cmdk-open');
    input.value = '';
    render('');
    setTimeout(() => input.focus(), 20);
  }
  function close() {
    overlay.classList.remove('cmdk-open');
    input.blur();
  }
  function isOpen() { return overlay.classList.contains('cmdk-open'); }

  function render(q) {
    filtered = commands
      .map(c => ({ c, s: Math.max(score(q, c.title), score(q, c.sub) * 0.6) }))
      .filter(x => x.s > 0)
      .sort((a, b) => b.s - a.s)
      .map(x => x.c);
    active = 0;
    if (!filtered.length) {
      list.innerHTML = '<div class="cmdk-empty">No matches</div>';
      return;
    }
    list.innerHTML = filtered.map((c, i) => `
      <div class="cmdk-item${i === active ? ' active' : ''}" data-i="${i}">
        <span class="cmdk-kind ${c.kind}">${c.kind === 'page' ? 'Go' : 'Run'}</span>
        <span class="cmdk-item-body">
          <span class="cmdk-item-title">${c.title}</span>
          <span class="cmdk-item-sub">${c.sub}</span>
        </span>
      </div>`).join('');
    list.querySelectorAll('.cmdk-item').forEach(el => {
      el.addEventListener('mousemove', () => setActive(+el.dataset.i));
      el.addEventListener('click', () => exec(+el.dataset.i));
    });
  }

  function setActive(i) {
    active = i;
    list.querySelectorAll('.cmdk-item').forEach((el, idx) => el.classList.toggle('active', idx === active));
  }

  function exec(i) {
    const c = filtered[i];
    if (!c) return;
    close();
    setTimeout(() => c.run(), 60);
  }

  document.addEventListener('DOMContentLoaded', () => {
    overlay = document.getElementById('cmdk');
    input = document.getElementById('cmdk-input');
    list = document.getElementById('cmdk-list');
    if (!overlay || !input || !list) return;

    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    input.addEventListener('input', () => render(input.value.trim()));
    input.addEventListener('keydown', e => {
      if (e.key === 'ArrowDown') { e.preventDefault(); setActive(Math.min(active + 1, filtered.length - 1)); scrollActive(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(Math.max(active - 1, 0)); scrollActive(); }
      else if (e.key === 'Enter') { e.preventDefault(); exec(active); }
      else if (e.key === 'Escape') { e.preventDefault(); close(); }
    });

    function scrollActive() {
      list.querySelector('.cmdk-item.active')?.scrollIntoView({ block: 'nearest' });
    }

    // Global hotkey: ⌘K / Ctrl+K
    document.addEventListener('keydown', e => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        isOpen() ? close() : open();
      }
    });

    // Topbar hint button
    document.getElementById('cmdk-hint')?.addEventListener('click', open);

    window.openCommandPalette = open;
  });
})();
