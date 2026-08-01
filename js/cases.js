// ═══════════════════════════════════════════════════
//  cases.js — Investigation Cases: group indicators (IPs,
//  domains, hashes, URLs) + notes into named cases.
//  Guest → localStorage; signed in → Firestore (synced per
//  user) via GAuth.store. No inline handlers (CSP-safe).
// ═══════════════════════════════════════════════════
(function () {
  'use strict';

  const KEY = 'sentinelx_cases';
  const signedIn = () => !!(window.GAuth && GAuth.isSignedIn());
  const esc = (s) => window.escHtml(s ?? '');
  const isLocal = (id) => String(id).startsWith('local-');

  let selectedId = null;

  const load = () => { try { return JSON.parse(localStorage.getItem(KEY)) || []; } catch { return []; } };
  const save = (list) => localStorage.setItem(KEY, JSON.stringify(list));

  // ── Mutations (localStorage always; mirror to Firestore when signed in) ──
  async function createCase() {
    const c = { name: 'Untitled case', notes: '', items: [], created: new Date().toISOString() };
    if (signedIn()) { try { c.id = await GAuth.store.addCase(c); } catch { c.id = 'local-' + Date.now(); } }
    else c.id = 'local-' + Date.now();
    const list = load(); list.unshift(c); save(list);
    selectedId = c.id; render();
  }

  // Save a field change. Never re-renders the detail panel (would clobber the
  // input the user is typing in); callers refresh sub-sections as needed.
  async function patchCase(id, patch) {
    const list = load();
    const c = list.find(x => x.id === id); if (!c) return;
    Object.assign(c, patch); save(list); renderList();
    if (signedIn() && !isLocal(id)) { try { await GAuth.store.updateCase(id, patch); } catch {} }
  }

  async function removeCase(id) {
    if (!id || !confirm('Delete this case?')) return;
    save(load().filter(x => x.id !== id));
    if (selectedId === id) selectedId = null;
    render();
    if (signedIn() && !isLocal(id)) { try { await GAuth.store.deleteCase(id); } catch {} }
  }

  // ── Sign-in hydrate: push guest cases up first (no data loss), then load all ──
  window.hydrateCasesFromServer = async () => {
    if (!signedIn()) return;
    try {
      for (const c of load().filter(x => isLocal(x.id))) {
        const { id, ...data } = c;
        await GAuth.store.addCase(data);
      }
      save(await GAuth.store.listCases());
      render();
    } catch (e) { console.warn('cases hydrate failed:', e); }
  };

  // ── Render ──
  function render() { renderList(); renderDetail(); }

  function renderList() {
    const el = document.getElementById('cases-list'); if (!el) return;
    const list = load();
    el.innerHTML = list.length ? list.map(c => `
      <button class="case-item${c.id === selectedId ? ' active' : ''}" data-case="${esc(c.id)}">
        <span class="case-item-name">${esc(c.name || 'Untitled')}</span>
        <span class="case-item-count">${(c.items || []).length}</span>
      </button>`).join('') : '<div class="cases-empty-sm">No cases yet</div>';
  }

  function itemsHTML(items) {
    return items.length ? items.map((it, i) => `
      <div class="case-item-row">
        <span class="mono">${esc(it.value)}</span>
        <button class="remove-btn" data-item="${i}">Remove</button>
      </div>`).join('') : '<div class="cases-empty-sm">No indicators yet</div>';
  }

  function renderItems() {
    const box = document.querySelector('#cases-detail .case-items'); if (!box) return;
    box.innerHTML = itemsHTML((load().find(x => x.id === selectedId)?.items) || []);
  }

  function renderDetail() {
    const el = document.getElementById('cases-detail'); if (!el) return;
    const c = load().find(x => x.id === selectedId);
    if (!c) {
      el.innerHTML = `<div class="cases-empty">
        <div class="cases-empty-title">No case selected</div>
        <div class="cases-empty-sub">Create a case to collect the IPs, domains, hashes and notes from an investigation in one place${signedIn() ? ' — synced to your account' : ''}.</div>
      </div>`;
      return;
    }
    el.innerHTML = `
      <div class="case-head">
        <input class="case-name-input" id="case-name" value="${esc(c.name || '')}" placeholder="Case name"/>
        <button class="panel-btn" id="case-report" title="Download an incident report (markdown)">Report</button>
        <button class="panel-btn" id="case-sigma" title="Generate a Sigma detection rule from the indicators">Sigma</button>
        <button class="panel-btn danger-btn" id="case-delete">Delete</button>
      </div>
      <div class="case-add">
        <input class="tool-input" id="case-item-input" placeholder="Add an IP, domain, hash, URL…"/>
        <button class="panel-btn" id="case-item-add">Add</button>
      </div>
      <div class="case-items">${itemsHTML(c.items || [])}</div>
      <label class="case-notes-label">Notes</label>
      <textarea class="case-notes" id="case-notes" placeholder="Findings, timeline, conclusions…">${esc(c.notes || '')}</textarea>`;
  }

  function addItem() {
    const inp = document.getElementById('case-item-input');
    const v = inp?.value.trim(); if (!v || !selectedId) return;
    const c = load().find(x => x.id === selectedId); if (!c) return;
    patchCase(selectedId, { items: [...(c.items || []), { value: v, added: new Date().toISOString() }] });
    renderItems();
    const box = document.getElementById('case-item-input');
    if (box) { box.value = ''; box.focus(); }
  }

  // ── Exports: incident report (markdown) + Sigma detection rule ──
  const dl = (name, text, mime = 'text/plain') => {
    const url = URL.createObjectURL(new Blob([text], { type: mime }));
    const a = document.createElement('a');
    a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
  };
  const slug = (s) => (s || 'case').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'case';

  const IP_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
  const HASH_RE = /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i;
  function splitIndicators(items) {
    const out = { ips: [], hashes: [], domains: [], other: [] };
    for (const it of items || []) {
      const v = it.value.trim();
      if (IP_RE.test(v) || (v.includes(':') && /^[0-9a-f:]+$/i.test(v))) out.ips.push(v);
      else if (HASH_RE.test(v)) out.hashes.push(v.toLowerCase());
      else if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) out.domains.push(v.toLowerCase());
      else out.other.push(v);
    }
    return out;
  }

  function exportReport(c) {
    const rows = (c.items || []).map(it =>
      `| \`${it.value.replace(/\|/g, '\\|')}\` | ${(it.added || '').slice(0, 10)} |`).join('\n');
    const md = `# Incident Report — ${c.name || 'Untitled case'}

- **Case opened:** ${(c.created || '').slice(0, 10) || 'unknown'}
- **Report generated:** ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC
- **Indicators:** ${(c.items || []).length}

## Indicators of Compromise

| Indicator | Added |
|---|---|
${rows || '| _none recorded_ | |'}

## Analyst Notes

${c.notes || '_No notes recorded._'}

---
_Generated by SentinelX._
`;
    dl(`case-${slug(c.name)}.md`, md, 'text/markdown');
  }

  function exportSigma(c) {
    const { ips, domains } = splitIndicators(c.items);
    if (!ips.length && !domains.length) {
      (window.showToast || (() => {}))('Sigma needs at least one IP or domain indicator', 'warn');
      return;
    }
    const list = (arr) => arr.map(v => `            - '${v}'`).join('\n');
    const yml = `title: Network contact with "${(c.name || 'Untitled').replace(/"/g, '')}" indicators
id: ${crypto.randomUUID()}
status: experimental
description: >
    Auto-generated from a SentinelX investigation case. Matches network
    connections to the IPs/domains collected in the case. Review before
    deploying — thresholds and fields depend on your log source.
author: SentinelX
date: ${new Date().toISOString().slice(0, 10)}
logsource:
    category: network_connection
detection:${ips.length ? `
    selection_ip:
        DestinationIp:
${list(ips)}` : ''}${domains.length ? `
    selection_domain:
        DestinationHostname:
${list(domains)}` : ''}
    condition: ${[ips.length && 'selection_ip', domains.length && 'selection_domain'].filter(Boolean).join(' or ')}
falsepositives:
    - Legitimate traffic to shared infrastructure
level: medium
`;
    dl(`case-${slug(c.name)}.sigma.yml`, yml);
  }

  // ── Events (delegated; CSP-safe) ──
  function init() {
    document.getElementById('case-new-btn')?.addEventListener('click', createCase);

    document.getElementById('cases-list')?.addEventListener('click', (e) => {
      const b = e.target.closest('[data-case]'); if (!b) return;
      selectedId = b.dataset.case; render();
    });

    const detail = document.getElementById('cases-detail');
    detail?.addEventListener('click', (e) => {
      if (e.target.closest('#case-delete')) return removeCase(selectedId);
      if (e.target.closest('#case-item-add')) return addItem();
      const c = () => load().find(x => x.id === selectedId);
      if (e.target.closest('#case-report')) { const x = c(); if (x) exportReport(x); return; }
      if (e.target.closest('#case-sigma')) { const x = c(); if (x) exportSigma(x); return; }
      const rm = e.target.closest('[data-item]');
      if (rm) {
        const c = load().find(x => x.id === selectedId); if (!c) return;
        patchCase(selectedId, { items: (c.items || []).filter((_, i) => i !== +rm.dataset.item) });
        renderItems();
      }
    });
    detail?.addEventListener('keydown', (e) => {
      if (e.target.id === 'case-item-input' && e.key === 'Enter') addItem();
    });
    // Debounced autosave for name + notes (no detail re-render → keeps focus)
    let t;
    detail?.addEventListener('input', (e) => {
      if (e.target.id !== 'case-name' && e.target.id !== 'case-notes') return;
      const patch = e.target.id === 'case-name' ? { name: e.target.value } : { notes: e.target.value };
      const id = selectedId; // capture now — user may switch cases before the debounce fires
      clearTimeout(t);
      t = setTimeout(() => patchCase(id, patch), 500);
    });

    render();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
