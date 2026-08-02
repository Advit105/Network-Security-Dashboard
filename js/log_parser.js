// ── Log Patterns ───────────────────────────────────
const PATTERNS = [
    {
        type: 'Brute Force',
        attack: ['T1110', 'Brute Force'],
        severity: 'danger',
        regex: /failed password|authentication failure|invalid password|too many failures/i,
        desc: ip => `Failed login attempt${ip ? ' from ' + ip : ''} — possible brute force attack`,
    },
    {
        type: 'Invalid User',
        attack: ['T1110', 'Brute Force — user guessing'],
        severity: 'danger',
        regex: /invalid user|unknown user|no such user/i,
        desc: ip => `Invalid username attempted${ip ? ' from ' + ip : ''}`,
    },
    {
        type: 'Port Scan',
        attack: ['T1046', 'Network Service Discovery'],
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
        attack: ['T1078', 'Valid Accounts'],
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
        attack: ['TA0002', 'Execution (tactic)'],
        severity: 'danger',
        regex: /malware|trojan|virus|backdoor|rootkit|exploit|payload/i,
        desc: ip => `Malware or suspicious activity detected`,
    },
    {
        type: 'Privilege Escalation',
        attack: ['T1548', 'Abuse Elevation Control'],
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
                    attack: pattern.attack || null,
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
let lastLogResults = null; // captured for the AI "Triage" button

function renderResults(results) {
    lastLogResults = results;
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
    summary.innerHTML += `<button class="panel-btn" id="log-triage" style="margin-left:auto" title="AI triage of these detections — needs a Claude API key (Settings → AI Assistant)">✦ AI Triage</button>`;

    // Result rows
    list.innerHTML = results.map((r, i) => `
    <div class="result-row" style="animation-delay:${i * 40}ms">
      <div class="alert-dot ${r.severity}"></div>
      <div class="result-info">
        <span class="result-type" style="color:var(--${r.severity === 'danger' ? 'red' : r.severity === 'warn' ? 'amber' : r.severity === 'success' ? 'green' : 'cyan'}-ink)">${r.type}</span>${r.attack ? ` <span class="attack-chip" title="MITRE ATT&CK — ${r.attack[1]}">${r.attack[0]}</span>` : ''}
        <span class="alert-msg">${r.desc}</span>
        <span class="result-raw">${escHtml(r.raw)}</span>
      </div>
      <span class="result-line">Line ${r.line}</span>
      <div class="alert-badge ${r.severity}">${r.severity === 'danger' ? 'Critical' : r.severity === 'warn' ? 'Warning' : r.severity === 'success' ? 'OK' : 'Info'}</div>
    </div>
  `).join('');

    panel.style.display = 'flex';
}

// ═══════════════════════════════════════════════════
//  THREAT ACTOR PIPELINE — extract IPs → geolocate → block
// ═══════════════════════════════════════════════════
// Geolocation is shared via window.SentinelGeo (util.js).

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
        const wasCached = SentinelGeo.cached(a.ip);
        const geo = await SentinelGeo(a.ip);
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
        showToast(added ? `Blocked ${added} IP${added === 1 ? '' : 's'} — see Top Threat Origins` : 'All actors already blocked', added ? 'success' : 'info');
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

// ── AI triage of the parsed detections (shared window.AI) ──
async function aiTriage() {
    if (!window.AI || !lastLogResults || !lastLogResults.length) return;
    const title = 'AI Log Triage';
    if (!AI.requireKey()) return;
    const counts = { danger: 0, warn: 0, success: 0, info: 0 };
    lastLogResults.forEach(r => counts[r.severity]++);
    const byType = {};
    lastLogResults.forEach(r => {
        const k = r.attack ? `${r.type} [${r.attack[0]} ${r.attack[1]}]` : r.type;
        byType[k] = (byType[k] || 0) + 1;
    });
    const actors = buildActors(lastLogResults);
    const evidence = [
        `Detections: ${lastLogResults.length} lines flagged — ${counts.danger} critical, ${counts.warn} warning, ${counts.success} ok, ${counts.info} info.`,
        'Detection types:\n' + Object.entries(byType).map(([k, n]) => `- ${k} ×${n}`).join('\n'),
        actors.length
            ? 'Public source IPs:\n' + actors.slice(0, 15).map(a => `- ${a.ip}: ${a.hits} hit(s), mostly ${a.topPattern} (${a.worst})`).join('\n')
            : 'Public source IPs: none extracted (sources may be private/internal).',
    ].join('\n\n');
    AI.modal(title, '<div class="loading-row"><div class="spinner"></div><span>Triaging detections…</span></div>');
    try {
        const md = await AI.triageLog(evidence);
        AI.modal(title, `<div class="ai-md">${AI.mdToHtml(md)}</div>`);
    } catch (err) {
        AI.modal(title, `<div style="color:var(--red)">${escHtml(err.message)}</div>`);
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

    document.getElementById('results-panel')?.addEventListener('click', (e) => {
        if (e.target.closest('#log-triage')) aiTriage();
    });

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
        lastLogResults = null;
    });
});