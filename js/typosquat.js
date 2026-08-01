// ═══════════════════════════════════════════════════
//  typosquat.js — Look-alike / phishing domain scanner
//  Generates permutations of a domain, then resolves each
//  live via Google DNS-over-HTTPS to find registered ones.
//  100% client-side, real DNS answers, no API key.
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  const KEYBOARD_ADJACENT = {
    a: 'qsz', b: 'vgn', c: 'xdv', d: 'sfe', e: 'wrd', f: 'dgr', g: 'fht',
    h: 'gjy', i: 'uok', j: 'hkn', k: 'jlm', l: 'ko', m: 'nk', n: 'bm',
    o: 'ipl', p: 'ol', q: 'wa', r: 'etf', s: 'adw', t: 'rgy', u: 'yij',
    v: 'cb', w: 'qes', x: 'zc', y: 'tuh', z: 'xa',
  };
  const HOMOGLYPHS = {
    o: ['0'], l: ['1', 'i'], i: ['1', 'l'], e: ['3'], a: ['4'],
    s: ['5'], b: ['8'], g: ['9'], t: ['7'], m: ['rn'],
  };
  const ALT_TLDS = ['com', 'net', 'org', 'co', 'io', 'info', 'online', 'app', 'xyz', 'site', 'live'];

  // ── Generate candidate variants ───────────────────
  function generateVariants(sld, tld) {
    const out = new Map(); // domain -> technique
    const add = (name, technique) => {
      const full = name + '.' + tld;
      if (name && name !== sld && !out.has(full)) out.set(full, technique);
    };

    // 1. Character omission
    for (let i = 0; i < sld.length; i++) {
      add(sld.slice(0, i) + sld.slice(i + 1), 'Missing character');
    }
    // 2. Adjacent character swap (transposition)
    for (let i = 0; i < sld.length - 1; i++) {
      const a = sld.split('');
      [a[i], a[i + 1]] = [a[i + 1], a[i]];
      add(a.join(''), 'Transposed letters');
    }
    // 3. Character doubling
    for (let i = 0; i < sld.length; i++) {
      add(sld.slice(0, i) + sld[i] + sld.slice(i), 'Doubled character');
    }
    // 4. Keyboard-adjacent typo
    for (let i = 0; i < sld.length; i++) {
      const near = KEYBOARD_ADJACENT[sld[i]];
      if (near) for (const c of near) add(sld.slice(0, i) + c + sld.slice(i + 1), 'Fat-finger typo');
    }
    // 5. Homoglyph substitution
    for (let i = 0; i < sld.length; i++) {
      const subs = HOMOGLYPHS[sld[i]];
      if (subs) for (const s of subs) add(sld.slice(0, i) + s + sld.slice(i + 1), 'Homoglyph (look-alike)');
    }
    // 6. Hyphenation
    for (let i = 1; i < sld.length; i++) {
      add(sld.slice(0, i) + '-' + sld.slice(i), 'Inserted hyphen');
    }
    // 7. Common phishing prefixes/suffixes
    ['secure', 'login', 'account', 'verify', 'support', 'my'].forEach(w => {
      add(w + '-' + sld, 'Added keyword');
      add(sld + '-' + w, 'Added keyword');
    });

    return out;
  }

  // Same SLD across alternate TLDs
  function generateTldVariants(sld, tld) {
    const out = new Map();
    ALT_TLDS.forEach(t => {
      if (t !== tld) out.set(sld + '.' + t, 'Alternate TLD');
    });
    return out;
  }

  // ── Resolve one domain via Google DoH ─────────────
  async function resolves(domain) {
    try {
      const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`);
      if (!res.ok) return null;
      const d = await res.json();
      // Status 0 with an A-record Answer = registered & live
      if (d.Status === 0 && Array.isArray(d.Answer)) {
        const a = d.Answer.find(x => x.type === 1);
        if (a) return a.data;
      }
      return null;
    } catch {
      return null;
    }
  }

  // Small concurrency pool so we don't fire hundreds of requests at once
  async function mapPool(items, size, worker, onTick) {
    const results = [];
    let idx = 0, done = 0;
    async function run() {
      while (idx < items.length) {
        const i = idx++;
        results[i] = await worker(items[i], i);
        done++;
        onTick && onTick(done, items.length);
      }
    }
    await Promise.all(Array.from({ length: Math.min(size, items.length) }, run));
    return results;
  }

  // ── Main scan ─────────────────────────────────────
  async function scan(rawInput) {
    const input = (rawInput || '').trim().toLowerCase()
      .replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');

    const loading = document.getElementById('typo-loading');
    const errBox = document.getElementById('typo-error');
    const stats = document.getElementById('typo-stats-panel');
    const resultsPanel = document.getElementById('typo-results-panel');
    const progress = document.getElementById('typo-progress');
    const loadMsg = document.getElementById('typo-loading-msg');

    [stats, resultsPanel].forEach(el => el.style.display = 'none');
    errBox.style.display = 'none';

    const parts = input.split('.');
    if (parts.length < 2 || !parts[0] || !parts[parts.length - 1]) {
      errBox.style.display = 'flex';
      document.getElementById('typo-error-msg').textContent = 'Enter a valid domain, e.g. paypal.com';
      return;
    }

    let tld = parts.pop();
    // ccTLD registries like .co.uk: keep the two-part suffix together so
    // variants mutate "example", not "co". Common seconds only — good enough.
    const SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'ac', 'gov', 'edu']);
    if (parts.length > 1 && tld.length === 2 && SECOND_LEVEL.has(parts[parts.length - 1])) {
      tld = parts.pop() + '.' + tld;
    }
    const sld = parts.join('');

    loading.style.display = 'flex';
    progress.style.width = '0%';

    // Build the full candidate set
    const variants = new Map([
      ...generateVariants(sld, tld),
      ...generateTldVariants(sld, tld),
    ]);
    const list = [...variants.entries()].map(([domain, technique]) => ({ domain, technique }));

    loadMsg.textContent = `Resolving ${list.length} variants of ${sld}.${tld}…`;

    const registered = [];
    await mapPool(list, 8, async (v) => {
      const ip = await resolves(v.domain);
      if (ip) registered.push({ ...v, ip });
      return ip;
    }, (done, total) => {
      progress.style.width = (done / total * 100).toFixed(1) + '%';
    });

    loading.style.display = 'none';

    // Stats
    document.getElementById('typo-stat-total').textContent = list.length;
    document.getElementById('typo-stat-registered').textContent = registered.length;
    document.getElementById('typo-stat-available').textContent = list.length - registered.length;
    stats.style.display = 'grid';

    // Results table
    registered.sort((a, b) => a.domain.localeCompare(b.domain));
    const tbody = document.getElementById('typo-tbody');
    const count = document.getElementById('typo-results-count');
    count.textContent = `${registered.length} found`;

    if (registered.length === 0) {
      resultsPanel.style.display = 'flex';
      tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:18px;color:var(--green)">✓ No registered look-alike domains resolved. None of the tested variants are live.</td></tr>`;
      return;
    }

    tbody.innerHTML = registered.map(r => `
      <tr>
        <td class="mono" style="color:var(--red)">${escHtml(r.domain)}</td>
        <td style="font-size:11px">${r.technique}</td>
        <td class="mono" style="font-size:11px">${escHtml(r.ip)}</td>
        <td>
          <button class="remove-btn typo-invest-ip" style="background:var(--cyan-bg);border-color:rgba(0,229,255,0.25);color:var(--cyan)" data-ip="${escHtml(r.ip)}">IP Lookup</button>
          <button class="remove-btn typo-invest-dns" style="background:var(--glass)" data-domain="${escHtml(r.domain)}">DNS</button>
        </td>
      </tr>
    `).join('');

    tbody.querySelectorAll('.typo-invest-ip').forEach(btn => {
      btn.addEventListener('click', () => {
        if (typeof navigateTo === 'function') navigateTo('ips');
        const inp = document.getElementById('ip-input');
        if (inp) inp.value = btn.dataset.ip;
        if (typeof lookupIP === 'function') lookupIP(btn.dataset.ip);
      });
    });
    tbody.querySelectorAll('.typo-invest-dns').forEach(btn => {
      btn.addEventListener('click', () => {
        if (typeof navigateTo === 'function') navigateTo('dns');
        const inp = document.getElementById('dns-input');
        if (inp) inp.value = btn.dataset.domain;
        if (typeof dnsLookup === 'function') dnsLookup(btn.dataset.domain, 'A');
      });
    });

    resultsPanel.style.display = 'flex';
  }

  // ── Wire up ───────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('typo-scan-btn');
    const input = document.getElementById('typo-input');
    btn?.addEventListener('click', () => scan(input.value));
    input?.addEventListener('keydown', e => { if (e.key === 'Enter') scan(input.value); });
    document.querySelectorAll('.quick-typo').forEach(b => {
      b.addEventListener('click', () => { input.value = b.dataset.domain; scan(b.dataset.domain); });
    });
  });
})();
