// ── Port Database ──────────────────────────────────
const PORT_DB = [
    { port: 21, service: 'FTP', risk: 'danger', desc: 'File Transfer — unencrypted, often exploited' },
    { port: 22, service: 'SSH', risk: 'warn', desc: 'Secure Shell — safe if hardened, common brute-force target' },
    { port: 23, service: 'Telnet', risk: 'danger', desc: 'Unencrypted remote access — should be disabled' },
    { port: 25, service: 'SMTP', risk: 'warn', desc: 'Mail transfer — can be abused for spam relay' },
    { port: 53, service: 'DNS', risk: 'info', desc: 'Domain Name System — monitor for DNS amplification' },
    { port: 80, service: 'HTTP', risk: 'warn', desc: 'Unencrypted web — redirect to HTTPS recommended' },
    { port: 110, service: 'POP3', risk: 'warn', desc: 'Email retrieval — unencrypted version' },
    { port: 135, service: 'MS-RPC', risk: 'danger', desc: 'Microsoft RPC — common Windows attack vector' },
    { port: 139, service: 'NetBIOS', risk: 'danger', desc: 'Windows file sharing — legacy, exploitable' },
    { port: 143, service: 'IMAP', risk: 'warn', desc: 'Email access — unencrypted version' },
    { port: 443, service: 'HTTPS', risk: 'success', desc: 'Encrypted web traffic — generally safe' },
    { port: 445, service: 'SMB', risk: 'danger', desc: 'Windows file share — EternalBlue exploit target' },
    { port: 993, service: 'IMAPS', risk: 'success', desc: 'Encrypted IMAP — safe' },
    { port: 995, service: 'POP3S', risk: 'success', desc: 'Encrypted POP3 — safe' },
    { port: 1433, service: 'MSSQL', risk: 'danger', desc: 'Microsoft SQL Server — should not be public' },
    { port: 3306, service: 'MySQL', risk: 'danger', desc: 'MySQL database — never expose publicly' },
    { port: 3389, service: 'RDP', risk: 'danger', desc: 'Remote Desktop — frequent ransomware entry point' },
    { port: 5432, service: 'PostgreSQL', risk: 'danger', desc: 'PostgreSQL — should not be publicly accessible' },
    { port: 5900, service: 'VNC', risk: 'danger', desc: 'Remote desktop — unencrypted, easy to exploit' },
    { port: 6379, service: 'Redis', risk: 'danger', desc: 'Redis cache — unauthenticated by default' },
    { port: 8080, service: 'HTTP-Alt', risk: 'warn', desc: 'Alternate HTTP — development servers often exposed' },
    { port: 8443, service: 'HTTPS-Alt', risk: 'info', desc: 'Alternate HTTPS — check what is running here' },
    { port: 27017, service: 'MongoDB', risk: 'danger', desc: 'MongoDB — historically exposed without auth' },
];

const RANGES = {
    common: PORT_DB.slice(0, 10),
    extended: PORT_DB.slice(0, 18),
    full: PORT_DB,
};

// ── Simulate Scan ──────────────────────────────────
function simulateScan(host, range) {
    const ports = RANGES[range];
    const opened = ports.filter(() => Math.random() > 0.45);
    return opened;
}

// ── Render Results ─────────────────────────────────
function renderScanResults(host, results) {
    const panel = document.getElementById('scan-results-panel');
    const tbody = document.getElementById('scan-tbody');
    const summary = document.getElementById('scan-summary');

    const counts = { danger: 0, warn: 0, success: 0, info: 0 };
    results.forEach(r => counts[r.risk]++);

    summary.innerHTML = `
    <span style="font-family:var(--font-mono);font-size:12px;color:var(--text-secondary)">${host}</span>
    ${counts.danger ? `<div class="alert-badge danger">${counts.danger} High</div>` : ''}
    ${counts.warn ? `<div class="alert-badge warn">${counts.warn} Med</div>` : ''}
    ${counts.success ? `<div class="alert-badge success">${counts.success} Safe</div>` : ''}
  `;

    tbody.innerHTML = results.map(r => `
    <tr>
      <td class="mono">${r.port}</td>
      <td style="color:var(--text-primary);font-weight:500">${r.service}</td>
      <td><span style="color:var(--success);font-family:var(--font-mono);font-size:11px">OPEN</span></td>
      <td><div class="alert-badge ${r.risk}">${r.risk === 'danger' ? 'High' : r.risk === 'warn' ? 'Med' : r.risk === 'success' ? 'Safe' : 'Info'}</div></td>
      <td style="font-size:12px;color:var(--text-secondary)">${r.desc}</td>
    </tr>
  `).join('');

    panel.style.display = 'flex';
}

// ── Progress Animation ─────────────────────────────
function animateScan(host, range, callback) {
    const progressWrap = document.getElementById('scan-progress');
    const progressFill = document.getElementById('progress-fill');
    const progressLabel = document.getElementById('progress-label');
    const btn = document.getElementById('scan-btn');

    btn.disabled = true;
    progressWrap.style.display = 'block';
    document.getElementById('scan-results-panel').style.display = 'none';

    const steps = [
        'Resolving host...',
        'Sending SYN packets...',
        'Waiting for responses...',
        'Analysing open ports...',
        'Generating report...',
    ];

    let pct = 0;
    let step = 0;
    progressLabel.textContent = steps[0];

    const interval = setInterval(() => {
        pct += Math.random() * 22 + 8;
        if (pct > 100) pct = 100;

        progressFill.style.width = pct + '%';

        const nextStep = Math.floor((pct / 100) * steps.length);
        if (nextStep < steps.length && nextStep !== step) {
            step = nextStep;
            progressLabel.textContent = steps[step];
        }

        if (pct >= 100) {
            clearInterval(interval);
            progressLabel.textContent = 'Scan complete.';
            btn.disabled = false;
            setTimeout(callback, 300);
        }
    }, 220);
}

// ── Event Listeners ────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('scan-btn').addEventListener('click', () => {
        const host = document.getElementById('scan-host').value.trim();
        const range = document.getElementById('scan-range').value;

        if (!host) {
            document.getElementById('scan-host').focus();
            return;
        }

        animateScan(host, range, () => {
            const results = simulateScan(host, range);
            renderScanResults(host, results);
        });
    });
});