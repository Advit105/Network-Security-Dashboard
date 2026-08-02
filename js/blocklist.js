// ── Storage Key ────────────────────────────────────
const STORAGE_KEY = 'sentinelx_blocklist';

// ── Load / Save ────────────────────────────────────
function loadBlocklist() {
    try {
        return JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
    } catch {
        return [];
    }
}

function saveBlocklist(list) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
}

// ── Refresh dependent views after any change ───────
function refreshBlocklistViews() {
    renderBlocklist();
    updateDashboardBlocklist();
    updateBlockedMetric();
    window.refreshWorldMap?.();
}

// Active remote store: Google (Firestore) → email backend → none (guest).
// Both stores expose the same add/remove/list shape, so callers don't care
// which one they get. null = guest, save to localStorage only.
function remoteStore() {
    if (window.GAuth && GAuth.isSignedIn()) return GAuth.store;
    if (window.SentinelAPI && SentinelAPI.isLoggedIn()) return SentinelAPI;
    return null;
}
const loggedIn = () => !!remoteStore();
const notify = (msg, kind) => (typeof showToast === 'function' ? showToast(msg, kind) : null);

// IPv4 or (rough) IPv6 — the server validates too, but guest mode has no
// server, so junk must be rejected here or it pollutes the list and map.
function isValidBlockIP(ip) {
    if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(ip)) return true;
    return ip.includes(':') && /^(?:[0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}$/i.test(ip);
}

// ── Add Entry ──────────────────────────────────────
// When signed in, the server is source of truth (per-user, synced); the entry it
// returns (with a real id) is mirrored into localStorage so the map/KPIs — which
// read localStorage — keep working unchanged. Offline/guest → localStorage only.
async function addToBlocklist(ip, reason = '', severity = 'danger') {
    if (!ip) return;
    ip = String(ip).trim();
    if (!isValidBlockIP(ip)) {
        notify(`"${ip.slice(0, 40)}" is not a valid IP address`, 'danger');
        return;
    }

    const list = loadBlocklist();
    if (list.find(e => e.ip === ip)) {
        notify(`${ip} is already in the blocklist`, 'warn');
        return;
    }

    const reasonText = reason || 'Manually blocked';

    const remote = remoteStore();
    if (remote) {
        try {
            const entry = await remote.addBlocklist(ip, reasonText, severity);
            list.unshift({ id: entry.id, ip: entry.ip, reason: entry.reason, severity: entry.severity, added: entry.created_at });
            saveBlocklist(list);
            refreshBlocklistViews();
            return;
        } catch (err) {
            if (err && err.status === 409) { notify(`${ip} is already blocked on your account`, 'warn'); return; }
            if (err && err.status === 422) { notify(`${ip} is not a valid IP address`, 'danger'); return; }
            notify('Server unreachable — saved to this device only', 'warn');
            // fall through to local save
        }
    }

    list.unshift({ ip, reason: reasonText, severity, added: new Date().toISOString() });
    saveBlocklist(list);
    refreshBlocklistViews();
}

// ── Remove Entry ───────────────────────────────────
async function removeFromBlocklist(ip) {
    const list = loadBlocklist();
    const entry = list.find(e => e.ip === ip);

    const remote = remoteStore();
    if (remote && entry && entry.id) {
        try { await remote.removeBlocklist(entry.id); }
        catch { notify('Sync unreachable — removed on this device only', 'warn'); }
    }

    saveBlocklist(list.filter(e => e.ip !== ip));
    refreshBlocklistViews();
}

// ── Clear All ──────────────────────────────────────
async function clearBlocklist() {
    if (!confirm('Remove all blocked IPs?')) return;

    const remote = remoteStore();
    if (remote) {
        for (const e of loadBlocklist()) {
            if (e.id) { try { await remote.removeBlocklist(e.id); } catch {} }
        }
    }

    saveBlocklist([]);
    refreshBlocklistViews();
}

// ── Replace the local mirror with the server's list (called on login) ──
function setBlocklistFromServer(serverList) {
    const mapped = (serverList || []).map(e => ({
        id: e.id, ip: e.ip, reason: e.reason, severity: e.severity, added: e.created_at,
    }));
    saveBlocklist(mapped);
    refreshBlocklistViews();
}

// ── Format Date ────────────────────────────────────
function formatDate(iso) {
    const d = new Date(iso);
    return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}

// ── Render Blocklist Table ─────────────────────────
function renderBlocklist() {
    const list = loadBlocklist();
    const tbody = document.getElementById('blocklist-tbody');
    const table = document.getElementById('blocklist-table');
    const empty = document.getElementById('blocklist-empty');
    const counter = document.getElementById('blocklist-count');

    if (!tbody) return;

    counter.textContent = `${list.length} ${list.length === 1 ? 'entry' : 'entries'}`;

    if (list.length === 0) {
        empty.style.display = 'block';
        table.style.display = 'none';
        return;
    }

    empty.style.display = 'none';
    table.style.display = 'table';

    // ip/reason are user data → escaped; Remove is a delegated listener on
    // the tbody (no inline onclick, so quotes in data can't break out).
    tbody.innerHTML = list.map(e => `
    <tr>
      <td class="mono">${escHtml(e.ip)}</td>
      <td style="color:var(--text-2);font-size:12px">${escHtml(e.reason)}</td>
      <td><div class="alert-badge ${e.severity}">${e.severity === 'danger' ? 'Critical' : e.severity === 'warn' ? 'Warning' : 'Info'}</div></td>
      <td style="font-family:var(--f-mono);font-size:11px;color:var(--text-3)">${formatDate(e.added)}</td>
      <td><button class="remove-btn" data-ip="${escHtml(e.ip)}">Remove</button></td>
    </tr>
  `).join('');
}

// ── Update Dashboard Blocklist Preview ────────────
function updateDashboardBlocklist() {
    const el = document.getElementById('dash-blocklist');
    const list = loadBlocklist();

    if (!el) return;

    if (list.length === 0) {
        el.innerHTML = `<div style="color:var(--text-3);font-size:12.5px;padding:8px 0">No blocks yet. Use the Log Analyzer or IP Lookup to identify threats, or add IPs directly in the Blocklist.</div>`;
        return;
    }

    el.innerHTML = list.slice(0, 4).map(e => `
    <div class="alert-row">
      <div class="alert-dot ${e.severity}"></div>
      <div class="alert-info">
        <span class="alert-msg" style="font-family:var(--f-mono);font-size:12px">${escHtml(e.ip)}</span>
        <span class="alert-meta">${escHtml(e.reason)}</span>
      </div>
      <div class="alert-badge ${e.severity}">${e.severity === 'danger' ? 'Critical' : e.severity === 'warn' ? 'Watch' : 'Info'}</div>
    </div>
  `).join('');
}

// ── Update Dashboard KPIs (values count up) ────────
function updateBlockedMetric() {
    const list = loadBlocklist();
    const critical = list.filter(e => e.severity === 'danger').length;
    const count = (id, val) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (typeof animateNumber === 'function') animateNumber(el, val); else el.textContent = val;
    };
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    count('kpi-blocked', list.length);
    set('kpi-blocked-count-label', list.length);
    count('kpi-critical', critical);
    set('kpi-critical-label', critical);
    const warn = list.filter(e => e.severity === 'warn').length;
    count('kpi-warn', warn);
    set('kpi-warn-label', warn);
    updateSeverityDonut(list);
}

// ── Dashboard severity donut (real blocklist data) ──
function updateSeverityDonut(list) {
    const svg = document.getElementById('sev-donut');
    if (!svg) return;
    list = list || loadBlocklist();

    const wrap = document.getElementById('sev-donut-wrap');
    const empty = document.getElementById('sev-empty');
    const badge = document.getElementById('sev-total-badge');
    const legend = document.getElementById('sev-legend');
    const total = list.length;

    if (badge) badge.textContent = `${total} blocked`;
    if (wrap) wrap.style.display = total ? '' : 'none';
    if (empty) empty.style.display = total ? 'none' : '';
    if (!total) return;

    const SEGS = [
        ['danger', 'Critical', 'var(--red)'],
        ['warn',   'Warning',  'var(--amber)'],
        ['info',   'Info',     'var(--cyan)'],
    ];
    const counts = Object.fromEntries(SEGS.map(([k]) => [k, 0]));
    list.forEach(e => { if (counts[e.severity] !== undefined) counts[e.severity]++; });

    // r=15.915 → circumference ≈ 100, so dash lengths are percentages
    let offset = 25; // start segments at 12 o'clock
    const rings = SEGS.filter(([k]) => counts[k] > 0).map(([k, , color]) => {
        const pct = (counts[k] / total) * 100;
        const c = `<circle cx="21" cy="21" r="15.915" fill="none" stroke-width="4.5"
            style="stroke:${color}" stroke-dasharray="${pct.toFixed(2)} ${(100 - pct).toFixed(2)}"
            stroke-dashoffset="${offset.toFixed(2)}"></circle>`;
        offset -= pct;
        return c;
    }).join('');

    svg.innerHTML = rings + `
        <text x="21" y="21" text-anchor="middle" dominant-baseline="central"
            style="fill:var(--text-1);font-family:var(--f-mono);font-size:9px;font-weight:600">${total}</text>`;

    if (legend) legend.innerHTML = SEGS.map(([k, name, color]) => `
        <div class="legend-row">
            <span class="legend-dot" style="background:${color}"></span>
            <span>${name}</span>
            <span class="legend-pct" style="color:${color}">${counts[k]}</span>
        </div>`).join('');
}

// ── Export (deployable formats) ────────────────────
const isV6 = (ip) => ip.includes(':');

function blocklistToFormat(list, fmt) {
    const now = new Date().toISOString();
    switch (fmt) {
        case 'plain':                                   // bare IPs, one per line
            return list.map(e => e.ip).join('\n') + '\n';
        case 'csv': {
            const q = (s) => `"${String(s ?? '').replace(/"/g, '""')}"`;
            return 'ip,severity,reason,added\n' +
                list.map(e => [e.ip, e.severity, e.reason, e.added].map(q).join(',')).join('\n') + '\n';
        }
        case 'iptables':                                // Linux netfilter drop rules (v4 + v6)
            return list.map(e => `${isV6(e.ip) ? 'ip6tables' : 'iptables'} -A INPUT -s ${e.ip} -j DROP`).join('\n') + '\n';
        case 'pf':                                      // BSD/macOS pf table
            return `table <sentinelx> persist { ${list.map(e => e.ip).join(', ')} }\nblock drop in quick from <sentinelx> to any\n`;
        case 'cisco':                                   // Cisco extended ACL entries
            return list.map(e => `deny ip host ${e.ip} any`).join('\n') + '\n';
        case 'stix': {                                  // STIX 2.1 bundle of indicators
            const objects = list.map(e => ({
                type: 'indicator', spec_version: '2.1',
                id: 'indicator--' + crypto.randomUUID(),
                created: now, modified: now,
                name: `Blocked ${e.ip}`, description: e.reason || '',
                indicator_types: ['malicious-activity'],
                pattern: `[${isV6(e.ip) ? 'ipv6-addr' : 'ipv4-addr'}:value = '${e.ip}']`,
                pattern_type: 'stix', valid_from: e.added || now,
            }));
            return JSON.stringify({ type: 'bundle', id: 'bundle--' + crypto.randomUUID(), objects }, null, 2);
        }
        default:                                        // txt — human-readable table
            return 'IP\tSEVERITY\tREASON\tDATE\n' +
                list.map(e => `${e.ip}\t${e.severity.toUpperCase()}\t${e.reason}\t${formatDate(e.added)}`).join('\n') + '\n';
    }
}

const EXPORT_META = {
    txt:      { ext: 'txt',  mime: 'text/plain' },
    plain:    { ext: 'txt',  mime: 'text/plain' },
    csv:      { ext: 'csv',  mime: 'text/csv' },
    iptables: { ext: 'sh',   mime: 'text/plain' },
    pf:       { ext: 'conf', mime: 'text/plain' },
    cisco:    { ext: 'txt',  mime: 'text/plain' },
    stix:     { ext: 'json', mime: 'application/json' },
};

function downloadBlocklist(fmt) {
    const list = loadBlocklist();
    if (list.length === 0) { notify('Blocklist is empty — nothing to export', 'warn'); return; }
    const meta = EXPORT_META[fmt] || EXPORT_META.txt;
    SentinelDownload(`sentinelx-blocklist.${meta.ext}`, blocklistToFormat(list, fmt), meta.mime);
}

// ── Event Listeners ────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Add IP button
    document.getElementById('add-block-btn').addEventListener('click', () => {
        const ip = document.getElementById('block-ip-input').value.trim();
        const reason = document.getElementById('block-reason-input').value.trim();
        const severity = document.getElementById('block-severity').value;

        if (!ip) {
            document.getElementById('block-ip-input').focus();
            return;
        }

        addToBlocklist(ip, reason, severity);

        // Clear inputs
        document.getElementById('block-ip-input').value = '';
        document.getElementById('block-reason-input').value = '';
    });

    // Enter key on IP input
    document.getElementById('block-ip-input').addEventListener('keydown', e => {
        if (e.key === 'Enter') document.getElementById('add-block-btn').click();
    });

    // Remove buttons (delegated — rows re-render on every change)
    document.getElementById('blocklist-tbody')?.addEventListener('click', e => {
        const btn = e.target.closest('.remove-btn');
        if (btn?.dataset.ip) removeFromBlocklist(btn.dataset.ip);
    });

    // Table search filter (folded in from the former search_filter.js)
    document.getElementById('blocklist-search')?.addEventListener('input', (e) => {
        const q = e.target.value.trim().toLowerCase();
        document.getElementById('blocklist-tbody')?.querySelectorAll('tr').forEach(row => {
            row.style.display = q && !row.textContent.toLowerCase().includes(q) ? 'none' : '';
        });
    });

    // Export menu (native <details>; each item carries data-export="<format>")
    document.getElementById('export-menu')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-export]');
        if (!btn) return;
        downloadBlocklist(btn.dataset.export);
        document.getElementById('export-menu').removeAttribute('open');
    });
    // Close the menu when clicking outside it
    document.addEventListener('click', (e) => {
        const m = document.getElementById('export-menu');
        if (m && m.open && !m.contains(e.target)) m.removeAttribute('open');
    });

    // Clear all
    document.getElementById('clear-all-btn').addEventListener('click', clearBlocklist);

    // Init on load
    renderBlocklist();
    updateDashboardBlocklist();
    updateBlockedMetric();
});