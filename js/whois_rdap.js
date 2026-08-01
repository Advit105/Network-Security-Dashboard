// ═══════════════════════════════════════════════════
//  whois_rdap.js — domain registration lookup via RDAP
//  (the modern, structured successor to WHOIS). RDAP is
//  CORS-enabled by spec, so this runs keyless in-browser
//  against rdap.org, which bootstraps to the right
//  registry/registrar server for any TLD.
//
//  The headline signal for SOC work is DOMAIN AGE: a
//  domain registered days ago is a classic phishing /
//  malware-C2 tell.
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);

  function cleanDomain(d) {
    return d.trim().toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '')
      .replace(/^www\./, '');
  }

  function daysBetween(a, b) { return Math.floor((b - a) / 86400000); }

  function ageText(days) {
    if (days < 0) return '—';
    if (days < 90)  return `${days} day${days === 1 ? '' : 's'}`;
    if (days < 730) return `${Math.floor(days / 30)} months`;
    return `${(days / 365).toFixed(1)} years`;
  }

  // Risk read purely from age — young domains are the flag
  function ageRisk(days) {
    if (days < 0) return { cls: 'info',   label: 'UNKNOWN AGE' };
    if (days <= 30)  return { cls: 'danger', label: 'VERY NEW — HIGH RISK' };
    if (days <= 90)  return { cls: 'warn',   label: 'RECENTLY REGISTERED' };
    if (days <= 365) return { cls: 'info',   label: 'ESTABLISHED (< 1 YR)' };
    return { cls: 'success', label: 'MATURE DOMAIN' };
  }

  function eventDate(events, action) {
    const e = (events || []).find(x => x.eventAction === action);
    return e ? e.eventDate : null;
  }

  function registrarName(entities) {
    const reg = (entities || []).find(e => (e.roles || []).includes('registrar'));
    if (!reg) return null;
    const fn = (reg.vcardArray?.[1] || []).find(f => f[0] === 'fn');
    return fn ? fn[3] : (reg.handle || null);
  }

  function fmt(dateStr) {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }

  async function lookup(domainRaw) {
    const domain = cleanDomain(domainRaw);
    if (!domain || !domain.includes('.')) { showError('Enter a valid domain, e.g. example.com'); return; }

    show('whois-loading'); hide('whois-error'); hide('whois-result');

    try {
      const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { redirect: 'follow' });
      if (res.status === 404) { hide('whois-loading'); showError(`No registration record found for ${domain} — it may be unregistered or an unsupported TLD.`); return; }
      if (!res.ok) throw new Error(`RDAP returned ${res.status}`);
      const d = await res.json();
      hide('whois-loading');
      renderResult(domain, d);
    } catch (err) {
      hide('whois-loading');
      showError(`Lookup failed: ${err.message}. Some ccTLDs don't publish RDAP data.`);
    }
  }

  function renderResult(domain, d) {
    const reg = eventDate(d.events, 'registration');
    const exp = eventDate(d.events, 'expiration');
    const chg = eventDate(d.events, 'last changed');
    const days = reg ? daysBetween(new Date(reg), new Date()) : -1;
    const risk = ageRisk(days);
    const dnssec = d.secureDNS?.delegationSigned;

    $('whois-domain').textContent = domain;
    $('whois-risk-badge').innerHTML = `<span class="alert-badge ${risk.cls}">${risk.label}</span>`;

    const set = (id, v) => { $(id).textContent = v; };
    set('whois-age', reg ? ageText(days) : '—');
    set('whois-registered', fmt(reg));
    set('whois-expires', fmt(exp));
    set('whois-changed', fmt(chg));
    set('whois-registrar', registrarName(d.entities) || '—');
    set('whois-dnssec', dnssec === true ? 'Signed' : dnssec === false ? 'Unsigned' : '—');

    // Colour the age value by risk
    $('whois-age').className = 'ip-detail-val';
    $('whois-age').style.color = `var(--${risk.cls === 'success' ? 'green' : risk.cls === 'danger' ? 'red' : risk.cls === 'warn' ? 'amber' : 'cyan'}-ink)`;

    const ns = (d.nameservers || []).map(n => n.ldhName).filter(Boolean);
    $('whois-ns').innerHTML = ns.length
      ? ns.map(h => `<span class="host-tag">${escHtml(h.toLowerCase())}</span>`).join('')
      : '<span class="exposure-none">none published</span>';

    const status = d.status || [];
    $('whois-status').innerHTML = status.length
      ? status.map(s => `<span class="subdomain-tag">${escHtml(s)}</span>`).join('')
      : '<span class="exposure-none">none</span>';

    show('whois-result');
  }

  function show(id) { const e = $(id); if (e) e.style.display = e.classList.contains('loading-row') ? 'flex' : ''; }
  function hide(id) { const e = $(id); if (e) e.style.display = 'none'; }
  function showError(msg) { $('whois-error-msg').textContent = msg; show('whois-error'); }

  document.addEventListener('DOMContentLoaded', () => {
    if (!$('whois-input')) return;
    $('whois-lookup-btn')?.addEventListener('click', () => lookup($('whois-input').value));
    $('whois-input')?.addEventListener('keydown', e => { if (e.key === 'Enter' && e.target.value.trim()) lookup(e.target.value); });
    document.querySelectorAll('.quick-whois').forEach(b =>
      b.addEventListener('click', () => { $('whois-input').value = b.dataset.domain; lookup(b.dataset.domain); }));
  });
})();
