// ── Storage Key ────────────────────────────────────
const STORAGE_KEY = 'sentinelx_blocklist';

// ── Load / Save ────────────────────────────────────
function loadBlocklist() {
    try {
        let data = localStorage.getItem(STORAGE_KEY);
        if (!data) {
            data = localStorage.getItem('netwatch_blocklist');
            if (data) {
                localStorage.setItem(STORAGE_KEY, data);
                localStorage.removeItem('netwatch_blocklist');
            }
        }
        return JSON.parse(data) || [];
    } catch {
        return [];
    }
}

function saveBlocklist(list) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
}

// ── Add Entry ──────────────────────────────────────
function addToBlocklist(ip, reason = '', severity = 'danger') {
    if (!ip) return;

    const list = loadBlocklist();

    // Prevent duplicates
    if (list.find(e => e.ip === ip)) {
        alert(`${ip} is already in the blocklist.`);
        return;
    }

    list.unshift({
        ip,
        reason: reason || 'Manually blocked',
        severity,
        added: new Date().toISOString(),
    });

    saveBlocklist(list);
    renderBlocklist();
    updateDashboardBlocklist();
    updateBlockedMetric();
}

// ── Remove Entry ───────────────────────────────────
function removeFromBlocklist(ip) {
    const list = loadBlocklist().filter(e => e.ip !== ip);
    saveBlocklist(list);
    renderBlocklist();
    updateDashboardBlocklist();
    updateBlockedMetric();
}

// ── Clear All ──────────────────────────────────────
function clearBlocklist() {
    if (!confirm('Remove all blocked IPs?')) return;
    saveBlocklist([]);
    renderBlocklist();
    updateDashboardBlocklist();
    updateBlockedMetric();
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
        el.innerHTML = `<div style="color:var(--text-muted);font-size:13px;padding:4px 0">No IPs blocked yet.</div>`;
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

// ── Update Dashboard Metric ────────────────────────
function updateBlockedMetric() {
    const count = loadBlocklist().length;
    const el = document.getElementById('blocked-metric-val');
    if (el) el.textContent = count;
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