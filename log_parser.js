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
    });

    document.getElementById('load-sample-btn').addEventListener('click', () => {
        document.getElementById('log-input').value = SAMPLE_LOGS;
    });

    document.getElementById('clear-btn').addEventListener('click', () => {
        document.getElementById('log-input').value = '';
        document.getElementById('results-panel').style.display = 'none';
        document.getElementById('results-list').innerHTML = '';
    });
});