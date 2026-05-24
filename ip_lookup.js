// ── IP Lookup via ip-api.com ───────────────────────
// Free tier: 45 requests/min, no API key needed

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

    try {
        const res = await fetch(`https://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,query`);
        const data = await res.json();

        loading.style.display = 'none';

        if (data.status === 'fail') {
            document.getElementById('ip-error-msg').textContent = `Lookup failed: ${data.message || 'Invalid IP address'}`;
            errBox.style.display = 'flex';
            return;
        }

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
        document.getElementById('ip-error-msg').textContent = 'Network error — could not reach ip-api.com. Check your internet connection.';
        errBox.style.display = 'flex';
    }
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

    // Quick test buttons
    document.querySelectorAll('.quick-btn').forEach(btn => {
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