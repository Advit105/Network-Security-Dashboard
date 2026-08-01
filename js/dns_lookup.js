// ── DNS Lookup via Google DNS API ──────────────────
// Endpoint: https://dns.google/resolve?name={domain}&type={type}
// Free, no API key required

const RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'];

async function dnsLookup(domain, type) {
    const loading = document.getElementById('dns-loading');
    const resultsPanel = document.getElementById('dns-results-panel');
    const errBox = document.getElementById('dns-error');

    loading.style.display = 'flex';
    resultsPanel.style.display = 'none';
    errBox.style.display = 'none';

    try {
        const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`);
        const data = await res.json();

        loading.style.display = 'none';

        if (data.Status !== 0 || !data.Answer || data.Answer.length === 0) {
            document.getElementById('dns-error-msg').textContent =
                data.Status !== 0 ? `DNS query failed (Status: ${data.Status}). Check the domain name.`
                                  : 'No records found for this query.';
            errBox.style.display = 'flex';
            return;
        }

        renderDNSResults(domain, type, data);
    } catch (err) {
        loading.style.display = 'none';
        document.getElementById('dns-error-msg').textContent = 'Network error — could not reach Google DNS. Check your internet connection.';
        errBox.style.display = 'flex';
    }
}

function getRecordTypeName(typeNum) {
    const types = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 15: 'MX', 16: 'TXT', 28: 'AAAA' };
    return types[typeNum] || `Type ${typeNum}`;
}

function renderDNSResults(domain, queryType, data) {
    const panel = document.getElementById('dns-results-panel');
    const tbody = document.getElementById('dns-tbody');
    const summary = document.getElementById('dns-summary');

    summary.innerHTML = `
        <span style="font-family:var(--f-mono);font-size:12px;color:var(--text-2)">${escHtml(domain)}</span>
        <div class="alert-badge info">${data.Answer.length} records</div>
        <div class="alert-badge success">${escHtml(queryType)}</div>
    `;

    tbody.innerHTML = data.Answer.map(record => {
        const typeName = getRecordTypeName(record.type);
        let value = record.data || '—';

        // Clean up TXT records (remove surrounding quotes)
        if (typeName === 'TXT' && value.startsWith('"') && value.endsWith('"')) {
            value = value.slice(1, -1);
        }

        // Truncate very long values
        const displayVal = value.length > 80 ? value.slice(0, 77) + '...' : value;

        // record.data / record.name are attacker-controlled (any domain's TXT
        // can contain markup) — always escaped before hitting innerHTML.
        return `
        <tr>
            <td><div class="alert-badge info" style="font-size:10px">${escHtml(typeName)}</div></td>
            <td style="font-family:var(--f-mono);font-size:12px;color:var(--text-1)">${escHtml(record.name)}</td>
            <td style="font-family:var(--f-mono);font-size:12px;color:var(--cyan-ink);word-break:break-all" title="${escHtml(value)}">${escHtml(displayVal)}</td>
            <td style="font-family:var(--f-mono);font-size:11px;color:var(--text-3)">${record.TTL}s</td>
        </tr>`;
    }).join('');

    panel.style.display = 'flex';
}

// ── Event Listeners ────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('dns-lookup-btn')?.addEventListener('click', () => {
        const domain = document.getElementById('dns-input').value.trim();
        const type = document.getElementById('dns-type').value;
        if (!domain) {
            document.getElementById('dns-input').focus();
            return;
        }
        dnsLookup(domain, type);
    });

    document.getElementById('dns-input')?.addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            const domain = e.target.value.trim();
            const type = document.getElementById('dns-type').value;
            if (domain) dnsLookup(domain, type);
        }
    });

    // Quick domain buttons
    document.querySelectorAll('.quick-domain').forEach(btn => {
        btn.addEventListener('click', () => {
            const domain = btn.dataset.domain;
            document.getElementById('dns-input').value = domain;
            dnsLookup(domain, document.getElementById('dns-type').value);
        });
    });

    // Lookup all record types at once
    document.getElementById('dns-all-btn')?.addEventListener('click', async () => {
        const domain = document.getElementById('dns-input').value.trim();
        if (!domain) {
            document.getElementById('dns-input').focus();
            return;
        }

        const loading = document.getElementById('dns-loading');
        const resultsPanel = document.getElementById('dns-results-panel');
        const errBox = document.getElementById('dns-error');

        loading.style.display = 'flex';
        resultsPanel.style.display = 'none';
        errBox.style.display = 'none';

        try {
            const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];
            const results = await Promise.all(
                types.map(t => fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${t}`)
                    .then(r => r.json())
                    .catch(() => null))
            );

            loading.style.display = 'none';

            const allAnswers = results
                .filter(r => r && r.Answer)
                .flatMap(r => r.Answer);

            if (allAnswers.length === 0) {
                document.getElementById('dns-error-msg').textContent = 'No DNS records found for this domain.';
                errBox.style.display = 'flex';
                return;
            }

            renderDNSResults(domain, 'ALL', { Answer: allAnswers });
        } catch {
            loading.style.display = 'none';
            document.getElementById('dns-error-msg').textContent = 'Network error — could not reach Google DNS.';
            errBox.style.display = 'flex';
        }
    });
});
