// ── IP Lookup via ipwho.is ─────────────────────────
// Free, keyless, works over HTTPS with CORS
// (ip-api.com returns 403 over HTTPS on the free tier)

const SUSPICIOUS_ORGS = [
    'tor', 'vpn', 'proxy', 'hosting', 'datacenter',
    'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner',
    'amazon', 'google cloud', 'azure', 'serverius',
];

function assessRisk(data) {
    const org = (data.org || '').toLowerCase();
    const isp = (data.isp || '').toLowerCase();

    const isSuspicious = SUSPICIOUS_ORGS.some(s =>
        org.includes(s) || isp.includes(s)
    );

    if (isSuspicious) return { level: 'danger', label: 'High Risk' };

    const highRiskCountries = ['CN', 'RU', 'KP', 'IR', 'SY'];
    if (highRiskCountries.includes(data.countryCode))
        return { level: 'warn', label: 'Elevated Risk' };

    return { level: 'success', label: 'Low Risk' };
}

async function lookupIP(ip) {
    const loading = document.getElementById('ip-loading');
    const result = document.getElementById('ip-result-panel');
    const errBox = document.getElementById('ip-error');

    // reset
    loading.style.display = 'flex';
    result.style.display = 'none';
    errBox.style.display = 'none';
    const shodanPanel = document.getElementById('ip-shodan-panel');
    if (shodanPanel) shodanPanel.style.display = 'none';

    try {
        const res = await fetch(`https://ipwho.is/${ip}`);
        const raw = await res.json();

        loading.style.display = 'none';

        if (!raw.success) {
            document.getElementById('ip-error-msg').textContent = `Lookup failed: ${raw.message || 'Invalid IP address'}`;
            errBox.style.display = 'flex';
            return;
        }

        // Normalize to the field names the rest of this file expects
        const data = {
            query: raw.ip,
            country: raw.country,
            countryCode: raw.country_code,
            regionName: raw.region,
            city: raw.city,
            lat: raw.latitude,
            lon: raw.longitude,
            timezone: raw.timezone?.id || '—',
            isp: raw.connection?.isp || '',
            org: raw.connection?.org || '',
        };

        const risk = assessRisk(data);

        // Populate fields
        document.getElementById('result-ip').textContent = data.query;
        document.getElementById('result-org').textContent = data.org || data.isp || '—';
        document.getElementById('result-country').textContent = `${data.country} (${data.countryCode})`;
        document.getElementById('result-region').textContent = data.regionName || '—';
        document.getElementById('result-city').textContent = data.city || '—';
        document.getElementById('result-timezone').textContent = data.timezone || '—';
        document.getElementById('result-isp').textContent = data.isp || '—';
        document.getElementById('result-coords').textContent = `${data.lat}, ${data.lon}`;

        document.getElementById('result-risk-badge').innerHTML =
            `<div class="alert-badge ${risk.level}">${risk.label}</div>`;

        result.style.display = 'block';

        // Real exposure data from Shodan's free InternetDB (keyless, CORS-open)
        lookupExposure(data.query);

        // Wire up action buttons with current IP data
        document.getElementById('block-ip-btn').onclick = () => {
            if (typeof addToBlocklist === 'function') {
                addToBlocklist(data.query, `Flagged via IP Lookup — ${data.org || data.isp}`, 'danger');
                navigateTo('blocklist');
            }
        };

        document.getElementById('watch-ip-btn').onclick = () => {
            if (typeof addToBlocklist === 'function') {
                addToBlocklist(data.query, `Under watch — ${data.city}, ${data.country}`, 'warn');
                navigateTo('blocklist');
            }
        };

        document.getElementById('copy-report-btn').onclick = () => {
            const report = `
IP Lookup Report — SentinelX
============================
IP Address : ${data.query}
Country    : ${data.country} (${data.countryCode})
Region     : ${data.regionName}
City       : ${data.city}
Timezone   : ${data.timezone}
ISP        : ${data.isp}
Org        : ${data.org}
Coordinates: ${data.lat}, ${data.lon}
Risk Level : ${risk.label}
      `.trim();
            navigator.clipboard.writeText(report);
            document.getElementById('copy-report-btn').textContent = 'Copied!';
            setTimeout(() => {
                document.getElementById('copy-report-btn').textContent = 'Copy Report';
            }, 2000);
        };

    } catch (err) {
        loading.style.display = 'none';
        document.getElementById('ip-error-msg').textContent = 'Network error — could not reach ipwho.is. Check your internet connection.';
        errBox.style.display = 'flex';
    }
}

// ── Exposure via Shodan InternetDB ─────────────────
// Free, keyless endpoint: open ports, known CVEs, tags, hostnames
// from Shodan's own internet-wide scans (no scanning done by us).
const KNOWN_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
    8080: 'HTTP-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB',
};

async function lookupExposure(ip) {
    const panel = document.getElementById('ip-shodan-panel');
    const body = document.getElementById('ip-shodan-body');
    if (!panel || !body) return;

    panel.style.display = 'block';
    body.innerHTML = '<div class="loading-row"><div class="spinner"></div><span>Querying exposure data…</span></div>';

    let d;
    try {
        const res = await fetch(`https://internetdb.shodan.io/${ip}`);
        if (res.status === 404) {
            body.innerHTML = '<div class="exposure-clean">✓ No exposed services found in Shodan\'s scan data for this IP.</div>';
            return;
        }
        if (!res.ok) throw new Error('HTTP ' + res.status);
        d = await res.json();
    } catch {
        body.innerHTML = '<div style="color:var(--text-3);font-size:12px;padding:8px 0">Exposure data unavailable (network error).</div>';
        return;
    }

    const ports = (d.ports || []).sort((a, b) => a - b);
    const vulns = d.vulns || [];
    const tags = d.tags || [];
    const hostnames = d.hostnames || [];

    if (!ports.length && !vulns.length && !tags.length) {
        body.innerHTML = '<div class="exposure-clean">✓ No exposed services, CVEs, or tags in Shodan\'s scan data.</div>';
        return;
    }

    let html = '<div class="exposure-grid">';

    // Open ports
    html += '<div class="exposure-block"><span class="exposure-label">Open Ports</span><div class="exposure-tags">';
    html += ports.length
        ? ports.map(p => {
            const name = KNOWN_PORTS[p];
            const risky = [23, 3389, 445, 5900, 6379, 27017, 9200, 3306, 5432, 1433].includes(p);
            return `<span class="port-tag${risky ? ' risky' : ''}" title="${name || 'port ' + p}">${p}${name ? ' · ' + name : ''}</span>`;
        }).join('')
        : '<span class="exposure-none">none</span>';
    html += '</div></div>';

    // Vulnerabilities
    html += '<div class="exposure-block"><span class="exposure-label">Known Vulnerabilities</span><div class="exposure-tags">';
    html += vulns.length
        ? vulns.slice(0, 20).map(v =>
            `<a class="cve-tag" href="https://nvd.nist.gov/vuln/detail/${v}" target="_blank" rel="noopener">${v}</a>`
          ).join('') + (vulns.length > 20 ? `<span class="exposure-none">+${vulns.length - 20} more</span>` : '')
        : '<span class="exposure-none">none reported</span>';
    html += '</div></div>';

    // Tags
    if (tags.length) {
        html += '<div class="exposure-block"><span class="exposure-label">Tags</span><div class="exposure-tags">';
        html += tags.map(t => `<span class="port-tag${['malware','c2','compromised','honeypot'].includes(t) ? ' risky' : ''}">${t}</span>`).join('');
        html += '</div></div>';
    }

    // Hostnames
    if (hostnames.length) {
        html += '<div class="exposure-block"><span class="exposure-label">Hostnames</span><div class="exposure-tags">';
        html += hostnames.slice(0, 8).map(h => `<span class="host-tag">${h}</span>`).join('');
        html += '</div></div>';
    }

    html += '</div>';

    // Summary line
    const flags = [];
    if (vulns.length) flags.push(`<strong style="color:var(--red)">${vulns.length} known CVE${vulns.length === 1 ? '' : 's'}</strong>`);
    if (ports.length) flags.push(`${ports.length} open port${ports.length === 1 ? '' : 's'}`);
    if (tags.some(t => ['malware','c2','compromised'].includes(t))) flags.push(`<strong style="color:var(--red)">flagged malicious</strong>`);
    if (flags.length) {
        html = `<div class="exposure-summary">${flags.join(' · ')}</div>` + html;
    }

    body.innerHTML = html;
}

// ── Detect My Public IP (ipify API) ────────────────
async function detectMyIP() {
    const input = document.getElementById('ip-input');
    const btn = document.getElementById('myip-btn');
    if (!input || !btn) return;

    btn.disabled = true;
    btn.textContent = 'Detecting...';

    try {
        const res = await fetch('https://api.ipify.org?format=json');
        const data = await res.json();
        input.value = data.ip;
        btn.textContent = 'My IP';
        btn.disabled = false;

        // Update dashboard stat if visible
        const dashEl = document.getElementById('dash-myip');
        if (dashEl) dashEl.textContent = data.ip;

        lookupIP(data.ip);
    } catch {
        btn.textContent = 'My IP';
        btn.disabled = false;
        if (typeof showToast === 'function') showToast('Could not detect your IP. Check internet connection.', 'warn');
    }
}

// ── Event Listeners ────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('lookup-btn')?.addEventListener('click', () => {
        const ip = document.getElementById('ip-input').value.trim();
        if (!ip) return;
        lookupIP(ip);
    });

    document.getElementById('ip-input')?.addEventListener('keydown', e => {
        if (e.key === 'Enter') lookupIP(e.target.value.trim());
    });

    document.getElementById('myip-btn')?.addEventListener('click', detectMyIP);

    // Quick test buttons — scoped to this page: .quick-btn is shared by the
    // DNS/SSL/Abuse pages, whose buttons have no data-ip.
    document.querySelectorAll('#page-ips .quick-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const ip = btn.dataset.ip;
            document.getElementById('ip-input').value = ip;
            lookupIP(ip);
        });
    });

    // Auto-detect IP on dashboard load for the stat
    fetch('https://api.ipify.org?format=json')
        .then(r => r.json())
        .then(d => {
            const el = document.getElementById('dash-myip');
            if (el) el.textContent = d.ip;
        })
        .catch(() => {});
});