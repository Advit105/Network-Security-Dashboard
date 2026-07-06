// ── Log Patterns ───────────────────────────────────
const PATTERNS = [
    {
        type: 'Brute Force',
        severity: 'danger',
        regex: /failed password|authentication failure|invalid password|too many failures/i,
        desc: ip => `Failed login attempt${ip ? ' from ' + ip : ''} — possible brute force attack`,
    },
    {
        type: 'Invalid User',
        severity: 'danger',
        regex: /invalid user|unknown user|no such user/i,
        desc: ip => `Invalid username attempted${ip ? ' from ' + ip : ''}`,
    },
    {
        type: 'Port Scan',
        severity: 'danger',
        regex: /port scan|nmap|syn flood|tcp scan|udp scan/i,
        desc: ip => `Port scan detected${ip ? ' from ' + ip : ''}`,
    },
    {
        type: 'Firewall Block',
        severity: 'warn',
        regex: /firewall.*drop|iptables.*drop|blocked|deny|reject/i,
        desc: ip => `Firewall blocked connection${ip ? ' from ' + ip : ''}`,
    },
    {
        type: 'Root Login',
        severity: 'danger',
        regex: /root.*login|login.*root|su.*root/i,
        desc: ip => `Root login attempt detected${ip ? ' from ' + ip : ''}`,
    },
    {
        type: 'Successful Login',
        severity: 'success',
        regex: /accepted password|session opened|login successful|authentication success/i,
        desc: ip => `Successful authentication${ip ? ' from ' + ip : ''}`,
    },
    {
        type: 'Malware / Suspicious Process',
        severity: 'danger',
        regex: /malware|trojan|virus|backdoor|rootkit|exploit|payload/i,
        desc: ip => `Malware or suspicious activity detected`,
    },
    {
        type: 'Privilege Escalation',
        severity: 'danger',
        regex: /sudo|privilege|escalat|NOPASSWD|sudoers/i,
        desc: ip => `Privilege escalation event detected`,
    },
    {
        type: 'Network Error',
        severity: 'warn',
        regex: /connection refused|connection timeout|network unreachable|no route/i,
        desc: ip => `Network connectivity issue detected`,
    },
    {
        type: 'Config Changed',
        severity: 'info',
        regex: /rule updated|config changed|policy applied|reloaded|restart/i,
        desc: ip => `System configuration was changed`,
    },
];

// ── IP Extractor ───────────────────────────────────
function extractIP(line) {
    const match = line.match(/\b(\d{1,3}\.){3}\d{1,3}\b/);
    return match ? match[0] : null;
}

// ── Public IP filter (skip private / reserved ranges) ─
function isPublicIP(ip) {
    const p = ip.split('.').map(Number);
    if (p.length !== 4 || p.some(o => isNaN(o) || o < 0 || o > 255)) return false;
    if (p[0] === 10) return false;                               // 10.0.0.0/8
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return false;  // 172.16.0.0/12
    if (p[0] === 192 && p[1] === 168) return false;              // 192.168.0.0/16
    if (p[0] === 127) return false;                              // loopback
    if (p[0] === 169 && p[1] === 254) return false;              // link-local
    if (p[0] === 0 || p[0] >= 224) return false;                 // reserved / multicast
    return true;
}

// ── Analyze ────────────────────────────────────────
function analyzeLogs(rawText) {
    const lines = rawText.split('\n').map((l, i) => ({ text: l.trim(), num: i + 1 }));
    const results = [];

    lines.forEach(({ text, num }) => {
        if (!text) return;
        for (const pattern of PATTERNS) {
            if (pattern.regex.test(text)) {
                results.push({
                    line: num,
                    type: pattern.type,
                    severity: pattern.severity,
                    desc: pattern.desc(extractIP(text)),
                    raw: text,
                });
                break;
            }
        }
    });

    return results;
}

// ── Render Results ─────────────────────────────────
function renderResults(results) {
    const panel = document.getElementById('results-panel');
    const list = document.getElementById('results-list');
    const summary = document.getElementById('results-summary');

    if (results.length === 0) {
        panel.style.display = 'flex';
        list.innerHTML = `<div style="padding:20px 0;text-align:center;color:var(--text-muted);font-size:13px">No suspicious patterns found in the logs.</div>`;
        summary.innerHTML = '';
        return;
    }

    // Count by severity
    const counts = { danger: 0, warn: 0, success: 0, info: 0 };
    results.forEach(r => counts[r.severity]++);

    // Summary badges
    summary.innerHTML = '';
    if (counts.danger) summary.innerHTML += `<div class="alert-badge danger">${counts.danger} Critical</div>`;
    if (counts.warn) summary.innerHTML += `<div class="alert-badge warn">${counts.warn} Warnings</div>`;
    if (counts.success) summary.innerHTML += `<div class="alert-badge success">${counts.success} OK</div>`;
    if (counts.info) summary.innerHTML += `<div class="alert-badge info">${counts.info} Info</div>`;

    // Result rows
    list.innerHTML = results.map((r, i) => `
    <div class="result-row" style="animation-delay:${i * 40}ms">
      <div class="alert-dot ${r.severity}"></div>
      <div class="result-info">
        <span class="result-type" style="color:var(--${r.severity === 'danger' ? 'danger' : r.severity === 'warn' ? 'warn' : r.severity === 'success' ? 'success' : 'info'})">${r.type}</span>
        <span class="alert-msg">${r.desc}</span>
        <span class="result-raw">${escapeHTML(r.raw)}</span>
      </div>
      <span class="result-line">Line ${r.line}</span>
      <div class="alert-badge ${r.severity}">${r.severity === 'danger' ? 'Critical' : r.severity === 'warn' ? 'Warning' : r.severity === 'success' ? 'OK' : 'Info'}</div>
    </div>
  `).join('');

    panel.style.display = 'flex';
}

function escapeHTML(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

// ═══════════════════════════════════════════════════
//  THREAT ACTOR PIPELINE — extract IPs → geolocate → block
// ═══════════════════════════════════════════════════
const GEO_CACHE_KEY = 'sentinelx_geo_cache_v2'; // shared with world_map.js

function loadGeoCacheLP() {
    try { return JSON.parse(localStorage.getItem(GEO_CACHE_KEY)) || {}; } catch { return {}; }
}
function cacheGeoLP(ip, entry) {
    const c = loadGeoCacheLP();
    c[ip] = entry;
    localStorage.setItem(GEO_CACHE_KEY, JSON.stringify(c));
}
async function geolocateLP(ip) {
    const cached = loadGeoCacheLP()[ip];
    if (cached) return cached;
    try {
        const res = await fetch(`https://ipwho.is/${ip}`);
        if (!res.ok) return { ok: false, transient: true };
        const d = await res.json();
        const entry = d.success
            ? { ok: true, lat: d.latitude, lon: d.longitude, city: d.city || '', country: d.country || '' }
            : { ok: false };
        cacheGeoLP(ip, entry);
        return entry;
    } catch {
        return { ok: false, transient: true };
    }
}

// Aggregate public attacker IPs from analysis results
function buildActors(results) {
    const map = {};
    results.forEach(r => {
        if (r.severity === 'success') return;       // don't flag successful logins
        const ip = extractIP(r.raw);
        if (!ip || !isPublicIP(ip)) return;
        if (!map[ip]) map[ip] = { ip, hits: 0, patterns: {}, worst: 'info' };
        map[ip].hits++;
        map[ip].patterns[r.type] = (map[ip].patterns[r.type] || 0) + 1;
        const rank = { danger: 3, warn: 2, info: 1 };
        if ((rank[r.severity] || 0) > (rank[map[ip].worst] || 0)) map[ip].worst = r.severity;
    });
    return Object.values(map)
        .map(a => ({ ...a, topPattern: Object.entries(a.patterns).sort((x, y) => y[1] - x[1])[0][0] }))
        .sort((a, b) => b.hits - a.hits);
}

let currentActors = [];

async function renderActors(results) {
    const panel = document.getElementById('log-actors-panel');
    const tbody = document.getElementById('log-actors-tbody');
    const count = document.getElementById('log-actors-count');
    if (!panel || !tbody) return;

    currentActors = buildActors(results);

    if (currentActors.length === 0) {
        panel.style.display = 'none';
        return;
    }

    panel.style.display = 'flex';
    count.textContent = `${currentActors.length} IP${currentActors.length === 1 ? '' : 's'}`;

    const blocked = new Set((typeof loadBlocklist === 'function' ? loadBlocklist() : []).map(e => e.ip));

    tbody.innerHTML = currentActors.map(a => `
      <tr data-ip="${a.ip}">
        <td class="mono">${a.ip}</td>
        <td><span class="alert-badge ${a.worst}" style="min-width:0">${a.hits}</span></td>
        <td class="actor-loc" style="font-size:11px;color:var(--text-3)">…</td>
        <td style="font-size:11px">${a.topPattern}</td>
        <td>${blocked.has(a.ip)
            ? '<span class="alert-badge danger">Blocked</span>'
            : `<button class="remove-btn actor-block-btn" style="background:var(--red-bg)" data-ip="${a.ip}" data-pattern="${a.topPattern}" data-sev="${a.worst}">Block</button>`}</td>
      </tr>
    `).join('');

    // Wire single-block buttons
    tbody.querySelectorAll('.actor-block-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            blockActor(btn.dataset.ip, btn.dataset.pattern, btn.dataset.sev);
            const cell = btn.closest('td');
            if (cell) cell.innerHTML = '<span class="alert-badge danger">Blocked</span>';
        });
    });

    // Geolocate each row live (cached, throttled)
    for (const a of currentActors) {
        const wasCached = !!loadGeoCacheLP()[a.ip];
        const geo = await geolocateLP(a.ip);
        const cell = tbody.querySelector(`tr[data-ip="${a.ip}"] .actor-loc`);
        if (cell) {
            cell.textContent = geo.ok
                ? [geo.city, geo.country].filter(Boolean).join(', ') || 'Unknown'
                : 'Unresolved';
            cell.style.color = geo.ok ? 'var(--text-2)' : 'var(--text-3)';
        }
        if (!wasCached) await new Promise(r => setTimeout(r, 150));
    }
}

function blockActor(ip, pattern, severity) {
    if (typeof addToBlocklist !== 'function') return;
    const sev = severity === 'danger' ? 'danger' : severity === 'warn' ? 'warn' : 'info';
    addToBlocklist(ip, `Log analysis — ${pattern}`, sev);
}

function blockAllActors() {
    if (!currentActors.length) return;
    const blocked = new Set((typeof loadBlocklist === 'function' ? loadBlocklist() : []).map(e => e.ip));
    let added = 0;
    currentActors.forEach(a => {
        if (blocked.has(a.ip)) return;
        blockActor(a.ip, a.topPattern, a.worst);
        added++;
    });
    if (typeof showToast === 'function') {
        showToast(added ? `Blocked ${added} IP${added === 1 ? '' : 's'} — see the Threat Origin Map` : 'All actors already blocked', added ? 'success' : 'info');
    }
    // Refresh the table to show Blocked state
    document.getElementById('log-actors-tbody')?.querySelectorAll('.actor-block-btn').forEach(btn => {
        const cell = btn.closest('td');
        if (cell) cell.innerHTML = '<span class="alert-badge danger">Blocked</span>';
    });
    if (added && typeof navigateTo === 'function') {
        setTimeout(() => navigateTo('dashboard'), 600);
    }
}

// ── Sample Logs ────────────────────────────────────
const SAMPLE_LOGS = `May 17 10:21:03 server sshd[1234]: Failed password for root from 192.168.1.104 port 22 ssh2
May 17 10:21:05 server sshd[1234]: Failed password for root from 192.168.1.104 port 22 ssh2
May 17 10:21:08 server sshd[1234]: Failed password for root from 192.168.1.104 port 22 ssh2
May 17 10:22:00 server sshd[1235]: Invalid user admin from 10.0.0.53 port 4444
May 17 10:22:45 server kernel: Firewall: DROP TCP 45.33.32.156:8080 -> 192.168.1.1:80
May 17 10:23:10 server sshd[1240]: Accepted password for deploy from 192.168.1.50 port 22 ssh2
May 17 10:24:00 server sudo: user1 : TTY=pts/0 ; NOPASSWD; USER=root ; COMMAND=/bin/bash
May 17 10:25:30 server nmap[9999]: TCP scan detected on host 10.0.0.1
May 17 10:26:00 server firewall: Rule updated - policy applied for zone external
May 17 10:27:11 server sshd[1260]: Invalid user guest from 91.198.174.192 port 55234
May 17 10:28:00 server kernel: connection refused from 185.220.101.5 port 443`;

// ── Event Listeners ────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('analyze-btn').addEventListener('click', () => {
        const raw = document.getElementById('log-input').value.trim();
        if (!raw) return;
        const results = analyzeLogs(raw);
        renderResults(results);
        renderActors(results);
    });

    document.getElementById('log-block-all-btn')?.addEventListener('click', blockAllActors);

    document.getElementById('load-sample-btn').addEventListener('click', () => {
        document.getElementById('log-input').value = SAMPLE_LOGS;
    });

    document.getElementById('clear-btn').addEventListener('click', () => {
        document.getElementById('log-input').value = '';
        document.getElementById('results-panel').style.display = 'none';
        document.getElementById('results-list').innerHTML = '';
        const actors = document.getElementById('log-actors-panel');
        if (actors) actors.style.display = 'none';
        currentActors = [];
    });
});