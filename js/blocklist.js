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

const loggedIn = () => !!(window.SentinelAPI && SentinelAPI.isLoggedIn());
const notify = (msg, kind) => (typeof showToast === 'function' ? showToast(msg, kind) : null);

// ── Add Entry ──────────────────────────────────────
// When signed in, the server is source of truth (per-user, synced); the entry it
// returns (with a real id) is mirrored into localStorage so the map/KPIs — which
// read localStorage — keep working unchanged. Offline/guest → localStorage only.
async function addToBlocklist(ip, reason = '', severity = 'danger') {
    if (!ip) return;

    const list = loadBlocklist();
    if (list.find(e => e.ip === ip)) {
        notify(`${ip} is already in the blocklist`, 'warn');
        return;
    }

    const reasonText = reason || 'Manually blocked';

    if (loggedIn()) {
        try {
            const entry = await SentinelAPI.addBlocklist(ip, reasonText, severity);
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

    if (loggedIn() && entry && entry.id) {
        try { await SentinelAPI.removeBlocklist(entry.id); }
        catch { notify('Server unreachable — removed on this device only', 'warn'); }
    }

    saveBlocklist(list.filter(e => e.ip !== ip));
    refreshBlocklistViews();
}

// ── Clear All ──────────────────────────────────────
async function clearBlocklist() {
    if (!confirm('Remove all blocked IPs?')) return;

    if (loggedIn()) {
        for (const e of loadBlocklist()) {
            if (e.id) { try { await SentinelAPI.removeBlocklist(e.id); } catch {} }
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

    tbody.innerHTML = list.map(e => `
    <tr>
      <td class="mono">${e.ip}</td>
      <td style="color:var(--text-secondary);font-size:12px">${e.reason}</td>
      <td><div class="alert-badge ${e.severity}">${e.severity === 'danger' ? 'Critical' : e.severity === 'warn' ? 'Warning' : 'Info'}</div></td>
      <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${formatDate(e.added)}</td>
      <td><button class="remove-btn" onclick="removeFromBlocklist('${e.ip}')">Remove</button></td>
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
        <span class="alert-msg" style="font-family:var(--font-mono);font-size:12px">${e.ip}</span>
        <span class="alert-meta">${e.reason}</span>
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

// ── Export ─────────────────────────────────────────
function exportBlocklist() {
    const list = loadBlocklist();
    if (list.length === 0) { alert('Blocklist is empty.'); return; }

    const text = list.map(e =>
        `${e.ip}\t${e.severity.toUpperCase()}\t${e.reason}\t${formatDate(e.added)}`
    ).join('\n');

    const blob = new Blob([`IP\tSEVERITY\tREASON\tDATE\n${text}`], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentinelx-blocklist.txt';
    a.click();
    URL.revokeObjectURL(url);
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

    // Export
    document.getElementById('export-btn').addEventListener('click', exportBlocklist);

    // Clear all
    document.getElementById('clear-all-btn').addEventListener('click', clearBlocklist);

    // Init on load
    renderBlocklist();
    updateDashboardBlocklist();
    updateBlockedMetric();
});