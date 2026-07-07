// ═══════════════════════════════════════════════════
//  asn_lookup.js — netblock / ASN / abuse-contact lookup
//  via RIPEstat (keyless, CORS-enabled). Answers the
//  operational question your IP Lookup can't: WHO owns
//  the range this attacker is in, and WHERE do I report
//  the abuse?
//
//  Three RIPEstat endpoints, fetched in parallel:
//   • network-info      → ASN + covering prefix
//   • as-overview       → the AS holder name + announced
//   • abuse-contact-finder → the abuse@ mailbox to report to
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const RS = 'https://stat.ripe.net/data';

  function validIP(ip) {
    return /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(ip);
  }

  async function jget(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`RIPEstat ${r.status}`);
    return (await r.json()).data;
  }

  async function lookup(ipRaw) {
    const ip = ipRaw.trim();
    if (!validIP(ip)) { showError('Enter a valid IPv4 address, e.g. 45.33.32.156'); return; }

    show('asn-loading'); hide('asn-error'); hide('asn-result');

    try {
      // network-info is the anchor; the other two enrich it
      const net = await jget(`${RS}/network-info/data.json?resource=${ip}`);
      const asn = (net.asns && net.asns[0]) || null;
      const prefix = net.prefix || '—';

      const [overview, abuse] = await Promise.all([
        asn ? jget(`${RS}/as-overview/data.json?resource=AS${asn}`).catch(() => null) : null,
        jget(`${RS}/abuse-contact-finder/data.json?resource=${ip}`).catch(() => null),
      ]);

      hide('asn-loading');
      render(ip, { asn, prefix, overview, abuse });
    } catch (err) {
      hide('asn-loading');
      showError(`Lookup failed: ${err.message}. RIPEstat may be busy — try again.`);
    }
  }

  function render(ip, d) {
    $('asn-ip').textContent = ip;
    $('asn-holder').textContent = d.overview?.holder || (d.asn ? '—' : 'Not announced / bogon');

    const set = (id, v) => { $(id).textContent = v; };
    set('asn-number', d.asn ? `AS${d.asn}` : '—');
    set('asn-prefix', d.prefix);
    set('asn-announced', d.overview ? (d.overview.announced ? 'Yes — globally routed' : 'No — not in the routing table') : '—');

    const abuseList = d.abuse?.abuse_contacts || [];
    const abuseWrap = $('asn-abuse');
    if (abuseList.length) {
      abuseWrap.innerHTML = abuseList.map(a => `
        <div class="asn-abuse-row">
          <span class="mono" style="color:var(--amber-ink)">${a}</span>
          <div style="display:flex;gap:6px">
            <button class="ioc-copy" onclick="navigator.clipboard.writeText('${a}').then(()=>showToast('Copied','success'))">Copy</button>
            <a class="ioc-copy" style="text-decoration:none" href="mailto:${a}?subject=Abuse%20report%20for%20${ip}&body=Hello%2C%0A%0AWe%20observed%20abusive%20activity%20from%20${ip}%20(prefix%20${encodeURIComponent(d.prefix)}).%0A">Report</a>
          </div>
        </div>`).join('');
    } else {
      abuseWrap.innerHTML = '<span class="exposure-none">No published abuse contact for this range.</span>';
    }

    // Cross-link to the existing IP geo/exposure lookup
    $('asn-pivot-ip').onclick = () => {
      navigateTo('ips');
      setTimeout(() => { const i = $('ip-input'); if (i) i.value = ip; $('lookup-btn')?.click(); }, 80);
    };

    show('asn-result');
  }

  function show(id) { const e = $(id); if (e) e.style.display = e.classList.contains('loading-row') ? 'flex' : ''; }
  function hide(id) { const e = $(id); if (e) e.style.display = 'none'; }
  function showError(msg) { $('asn-error-msg').textContent = msg; show('asn-error'); }

  async function useMyIP() {
    try {
      const ip = await (window.SentinelGetMyIP?.() ?? fetch('https://ipwho.is/').then(r => r.json()).then(j => j.ip));
      if (ip) { $('asn-input').value = ip; lookup(ip); }
    } catch { showError('Could not detect your IP.'); }
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!$('asn-input')) return;
    $('asn-lookup-btn')?.addEventListener('click', () => lookup($('asn-input').value));
    $('asn-myip-btn')?.addEventListener('click', useMyIP);
    $('asn-input')?.addEventListener('keydown', e => { if (e.key === 'Enter' && e.target.value.trim()) lookup(e.target.value); });
    document.querySelectorAll('.quick-asn').forEach(b =>
      b.addEventListener('click', () => { $('asn-input').value = b.dataset.ip; lookup(b.dataset.ip); }));
  });
})();
