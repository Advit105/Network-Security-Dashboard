// ═══════════════════════════════════════════════════
//  intel.js — Unified Threat Intel: paste any indicator
//  (IP / domain / URL / hash) → every keyless source at
//  once + an evidence-based exposure verdict.
//
//  Sources (all verified keyless + CORS, already in CSP):
//    ipwho.is (geo) · internetdb.shodan.io (ports/CVEs/tags)
//    dns.google (records, rDNS) · stat.ripe.net (ASN)
//    onionoo.torproject.org (Tor) · rdap.org (domain age)
//    crt.sh (certs)
//  Reputation feeds (VT, abuse.ch, GreyNoise) now require
//  keys AND block browser CORS (probed 2026-08-01), so
//  verdicts here are exposure-based — the caveat is shown,
//  and one-click pivots deep-link into those services.
//  Multi-line input with 2+ IPs → bulk triage table.
// ═══════════════════════════════════════════════════
(function () {
  'use strict';

  const esc = (s) => window.escHtml(s ?? '');
  let lastEvidence = null; // { kind, value, text } for the AI "Explain" button (single-indicator views only)

  // ── Indicator type detection ──────────────────────
  const RE = {
    ipv4: /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/,
    ipv6: /^(?:[0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}$/i,
    hash: /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i,
    domain: /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i,
  };
  function detect(raw) {
    const v = raw.trim().replace(/^hxxp/i, 'http').replace(/\[\.\]/g, '.');
    if (RE.ipv4.test(v)) return { type: 'ip', value: v };
    if (v.includes(':') && RE.ipv6.test(v)) return { type: 'ip', value: v };
    if (RE.hash.test(v)) return { type: 'hash', value: v.toLowerCase() };
    if (/^https?:\/\//i.test(v)) {
      try {
        const host = new URL(v).hostname;
        return RE.ipv4.test(host)
          ? { type: 'ip', value: host, from: 'url' }
          : { type: 'domain', value: host, from: 'url' };
      } catch { return null; }
    }
    if (RE.domain.test(v)) return { type: 'domain', value: v };
    return null;
  }

  // ── Fetch helpers (each returns null on failure — sources degrade independently) ──
  const jfetch = async (url, opts) => {
    try {
      const r = await fetch(url, opts);
      if (!r.ok) return r.status === 404 ? { __notFound: true } : null;
      return await r.json();
    } catch { return null; }
  };

  const geo = (ip) => window.SentinelGeo(ip);   // shared cached ipwho.is helper (util.js)
  const internetdb = (ip) => jfetch(`https://internetdb.shodan.io/${ip}`);
  const asnInfo = (ip) => jfetch(`https://stat.ripe.net/data/network-info/data.json?resource=${ip}`);
  const torCheck = (ip) => jfetch(`https://onionoo.torproject.org/summary?limit=4&search=${ip}`);
  const dnsQ = (name, type) => jfetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`);
  const rdap = (domain) => jfetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`);

  async function reverseDNS(ip) {
    if (ip.includes(':')) return null; // v6 nibble PTR skipped
    const arpa = ip.split('.').reverse().join('.') + '.in-addr.arpa';
    const d = await dnsQ(arpa, 'PTR');
    return d?.Answer?.[0]?.data?.replace(/\.$/, '') || null;
  }

  // ── Verdict synthesis (exposure-based; every signal is shown as evidence) ──
  const RISKY_PORTS = new Set([23, 445, 3389, 5900, 21]);
  function verdictFrom(signals) {
    const score = signals.reduce((s, x) => s + x.w, 0);
    if (score >= 4) return { label: 'HIGH RISK', cls: 'danger', score };
    if (score >= 2) return { label: 'SUSPICIOUS', cls: 'warn', score };
    if (score >= 1) return { label: 'LOW SIGNALS', cls: 'info', score };
    return { label: 'NO ADVERSE FINDINGS', cls: 'success', score };
  }

  function ipSignals(idb, tor, rdns) {
    const s = [];
    const vulns = idb?.vulns?.length || 0;
    const ports = idb?.ports || [];
    if (vulns) s.push({ w: 3, t: `${vulns} known CVE${vulns > 1 ? 's' : ''} on host` });
    const risky = ports.filter(p => RISKY_PORTS.has(p));
    if (risky.length) s.push({ w: 2, t: `high-risk port${risky.length > 1 ? 's' : ''} exposed: ${risky.join(', ')}` });
    if (ports.length > 10) s.push({ w: 1, t: `${ports.length} open ports (broad exposure)` });
    (idb?.tags || []).forEach(t => {
      if (['proxy', 'vpn', 'tor'].includes(t)) s.push({ w: 1, t: `tagged "${t}" by InternetDB` });
      if (t === 'eol-product') s.push({ w: 1, t: 'runs end-of-life software' });
    });
    if (tor?.relays?.length) s.push({ w: 2, t: 'active Tor relay' });
    if (rdns === null && idb && !idb.__notFound) s.push({ w: 0, t: 'no reverse DNS' });
    return s;
  }

  function domainSignals(ageDays, mx, txt, resolvedVulns) {
    const s = [];
    if (ageDays !== null) {
      if (ageDays < 30) s.push({ w: 3, t: `registered only ${ageDays} day${ageDays === 1 ? '' : 's'} ago` });
      else if (ageDays < 180) s.push({ w: 1, t: `young domain (${Math.round(ageDays / 30)} months old)` });
    }
    const spf = (txt || []).some(r => /v=spf1/i.test(r));
    if (mx !== null && !mx.length) s.push({ w: 1, t: 'no MX records (no real mail infra)' });
    if (txt !== null && !spf) s.push({ w: 1, t: 'no SPF record' });
    if (resolvedVulns) s.push({ w: 2, t: `resolves to host(s) with ${resolvedVulns} known CVEs` });
    return s;
  }

  // ── Rendering ─────────────────────────────────────
  const CAVEAT = 'Exposure-based assessment from keyless sources — not a malware-feed verdict. Confirm via the pivots below.';

  function card(title, bodyHtml) {
    return `<div class="intel-card"><div class="intel-card-title">${title}</div>${bodyHtml}</div>`;
  }
  const kv = (k, v) => v ? `<div class="intel-kv"><b>${k}</b><span>${v}</span></div>` : '';

  // Confidence reflects how complete the evidence is (which sources answered),
  // separate from the signal score (how adverse the findings are).
  function sourcesLine(meta) {
    if (!meta) return '';
    const list = meta.sources.map(s => {
      const color = s.ok === null ? 'var(--text-3)' : s.ok ? 'var(--green)' : 'var(--red)';
      const mark = s.ok === null ? '—' : s.ok ? '✓' : '✕';
      return `<span style="color:${color}">${esc(s.name)} ${mark}</span>`;
    }).join('<span style="color:var(--text-3)"> · </span>');
    return `<div class="intel-sources" style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:8px 0 2px;font-size:11px">
      <span class="alert-badge ${meta.confidence.cls}">${meta.confidence.label}</span>
      <span style="color:var(--text-3)">sources: ${list}</span></div>`;
  }

  function verdictBanner(v, signals, meta) {
    const ev = signals.filter(x => x.w > 0);
    return `
      <div class="intel-verdict ${v.cls}">
        <div class="intel-verdict-head"><span class="alert-badge ${v.cls}">${v.label}</span><span class="intel-score">signal score ${v.score}</span><button class="panel-btn intel-explain-btn" id="intel-explain" style="margin-left:auto" title="AI plain-English explanation — needs a Claude API key (Settings → AI Assistant)">✦ Explain</button></div>
        ${sourcesLine(meta)}
        ${ev.length ? `<ul class="intel-evidence">${ev.map(x => `<li>${esc(x.t)}</li>`).join('')}</ul>` : '<div class="intel-noev">No adverse signals in any queried source.</div>'}
        <div class="intel-caveat">${CAVEAT}</div>
      </div>`;
  }

  function pivots(type, value) {
    const v = encodeURIComponent(value);
    const ext = {
      ip: [['VirusTotal', `https://www.virustotal.com/gui/ip-address/${v}`], ['AbuseIPDB', `https://www.abuseipdb.com/check/${v}`], ['Shodan', `https://www.shodan.io/host/${v}`]],
      domain: [['VirusTotal', `https://www.virustotal.com/gui/domain/${v}`], ['urlscan.io', `https://urlscan.io/search/#${v}`]],
      hash: [['VirusTotal', `https://www.virustotal.com/gui/file/${v}`], ['MalwareBazaar', `https://bazaar.abuse.ch/browse.php?search=hash%3A${v}`]],
    }[type] || [];
    const internal = {
      ip: `<button class="ioc-pivot" data-pivot-page="ips" data-pivot-input="ip-input" data-pivot-btn="lookup-btn" data-pivot-val="${esc(value)}">IP Lookup</button>
           <button class="ioc-pivot" data-pivot-page="asn" data-pivot-input="asn-input" data-pivot-btn="asn-lookup-btn" data-pivot-val="${esc(value)}">ASN</button>
           <button class="ioc-pivot" data-block-ip="${esc(value)}">Block</button>`,
      domain: `<button class="ioc-pivot" data-pivot-page="dns" data-pivot-input="dns-input" data-pivot-btn="dns-lookup-btn" data-pivot-val="${esc(value)}">DNS</button>
               <button class="ioc-pivot" data-pivot-page="whois" data-pivot-input="whois-input" data-pivot-btn="whois-btn" data-pivot-val="${esc(value)}">WHOIS</button>`,
      hash: '',
    }[type] || '';
    return `<div class="intel-pivots">${internal}
      ${ext.map(([n, u]) => `<a class="ioc-pivot" href="${u}" target="_blank" rel="noopener">${n} ↗</a>`).join('')}
      <button class="ioc-copy" data-copy="${esc(value)}">Copy</button></div>`;
  }

  // ── Single-indicator enrichment ───────────────────
  async function enrichIP(ip, out) {
    const [g, idb, asn, tor, rdns] = await Promise.all([
      geo(ip), internetdb(ip), asnInfo(ip), torCheck(ip), reverseDNS(ip),
    ]);
    const signals = ipSignals(idb, tor, rdns);
    const v = verdictFrom(signals);
    const ports = idb?.ports || [];
    const vulns = idb?.vulns || [];
    lastEvidence = { kind: 'ip', value: ip, text: [
      `Exposure verdict: ${v.label} (signal score ${v.score})`,
      signals.filter(x => x.w > 0).length ? 'Signals:\n' + signals.filter(x => x.w > 0).map(x => '- ' + x.t).join('\n') : 'Signals: none',
      g?.ok ? `Geolocation: ${[g.city, g.country].filter(Boolean).join(', ') || '?'}; ISP ${g.isp || '?'}` : 'Geolocation: unavailable',
      asn?.data?.asns?.length ? `ASN: AS${asn.data.asns[0]}${asn.data.prefix ? ' (' + asn.data.prefix + ')' : ''}` : '',
      `Reverse DNS: ${rdns || 'none'}`,
      `Open ports: ${ports.length ? ports.join(', ') : 'none known'}`,
      `Known CVEs: ${vulns.length ? vulns.join(', ') : 'none known'}`,
      `InternetDB tags: ${(idb?.tags || []).join(', ') || 'none'}`,
      `Hostnames: ${(idb?.hostnames || []).slice(0, 5).join(', ') || 'none'}`,
      tor?.relays?.length ? 'Tor: active relay' : 'Tor: not a known relay',
    ].filter(Boolean).join('\n') };
    // Attribution: which sources answered → confidence in the exposure picture.
    const ipCore = [!!g, idb !== null, !!asn, tor !== null].filter(Boolean).length;
    const meta = {
      confidence: idb === null ? { label: 'LOW CONFIDENCE', cls: 'warn' }
        : ipCore >= 3 ? { label: 'HIGH CONFIDENCE', cls: 'success' }
        : { label: 'MEDIUM CONFIDENCE', cls: 'info' },
      sources: [
        { name: 'ipwho.is', ok: !!(g && g.ok) },
        { name: 'InternetDB', ok: idb !== null },
        { name: 'RIPE', ok: !!asn },
        { name: 'Tor', ok: tor !== null },
      ],
    };
    out.innerHTML = `
      ${verdictBanner(v, signals, meta)}
      ${pivots('ip', ip)}
      <div class="intel-grid">
        ${card('Geolocation', g?.ok
          ? kv('Location', esc([g.city, g.country].filter(Boolean).join(', '))) + kv('ISP', esc(g.isp))
          : '<div class="intel-noev">unavailable</div>')}
        ${card('Network', (asn?.data?.asns?.length ? kv('ASN', 'AS' + esc(String(asn.data.asns[0]))) : '') + kv('Prefix', esc(asn?.data?.prefix || '')) + kv('Reverse DNS', esc(rdns || '—')) || '<div class="intel-noev">unavailable</div>')}
        ${card('Exposure (InternetDB)', idb && !idb.__notFound
          ? kv('Open ports', ports.length ? ports.map(p => `<span class="mono">${p}</span>`).join(' ') : 'none known')
            + kv('CVEs', vulns.length ? vulns.slice(0, 6).map(c => `<a href="https://nvd.nist.gov/vuln/detail/${esc(c)}" target="_blank" rel="noopener">${esc(c)}</a>`).join(' ') + (vulns.length > 6 ? ` +${vulns.length - 6} more` : '') : 'none known')
            + kv('Tags', (idb.tags || []).map(esc).join(', ') || '—')
            + kv('Hostnames', (idb.hostnames || []).slice(0, 3).map(esc).join(', ') || '—')
          : '<div class="intel-noev">not in InternetDB (no known exposure)</div>')}
        ${card('Tor', tor?.relays?.length ? kv('Relay', 'yes — ' + esc(tor.relays[0].n || 'unnamed')) : '<div class="intel-noev">not a known Tor relay</div>')}
      </div>`;
  }

  async function enrichDomain(domain, out) {
    const [a, aaaa, ns, mxr, txtr, reg] = await Promise.all([
      dnsQ(domain, 'A'), dnsQ(domain, 'AAAA'), dnsQ(domain, 'NS'), dnsQ(domain, 'MX'), dnsQ(domain, 'TXT'), rdap(domain),
    ]);
    const ips = [...(a?.Answer || []), ...(aaaa?.Answer || [])].filter(r => r.type === 1 || r.type === 28).map(r => r.data);
    const mx = mxr === null ? null : (mxr?.Answer || []).map(r => r.data);
    const txt = txtr === null ? null : (txtr?.Answer || []).map(r => r.data);
    // registration date → age
    let ageDays = null, regDate = null;
    const ev = reg?.events?.find(e => e.eventAction === 'registration');
    if (ev?.eventDate) { regDate = ev.eventDate.slice(0, 10); ageDays = Math.floor((Date.now() - Date.parse(ev.eventDate)) / 864e5); }
    // pivot up to 3 resolved v4 IPs through InternetDB
    const pivotIPs = ips.filter(i => RE.ipv4.test(i)).slice(0, 3);
    const idbs = await Promise.all(pivotIPs.map(internetdb));
    const resolvedVulns = idbs.reduce((n, d) => n + (d?.vulns?.length || 0), 0);
    const signals = domainSignals(ageDays, mx, txt, resolvedVulns);
    const v = verdictFrom(signals);
    lastEvidence = { kind: 'domain', value: domain, text: [
      `Exposure verdict: ${v.label} (signal score ${v.score})`,
      signals.filter(x => x.w > 0).length ? 'Signals:\n' + signals.filter(x => x.w > 0).map(x => '- ' + x.t).join('\n') : 'Signals: none',
      `Resolves to: ${ips.length ? ips.slice(0, 6).join(', ') : 'does not resolve'}`,
      regDate ? `Registered: ${regDate} (${ageDays} days ago)` : 'Registration: RDAP unavailable',
      `MX: ${mx === null ? 'unavailable' : (mx.length ? mx.join(', ') : 'none')}`,
      `SPF: ${txt === null ? 'unavailable' : ((txt || []).some(r => /v=spf1/i.test(r)) ? 'present' : 'missing')}`,
      pivotIPs.length ? 'Resolved-host exposure:\n' + pivotIPs.map((ip, i) => `- ${ip}: ${idbs[i] && !idbs[i].__notFound ? `${(idbs[i].ports || []).length} ports, ${(idbs[i].vulns || []).length} CVEs` : 'no known exposure'}`).join('\n') : '',
      `Name servers: ${(ns?.Answer || []).slice(0, 4).map(r => r.data).join(', ') || 'unavailable'}`,
    ].filter(Boolean).join('\n') };
    const dnsOk = [a, aaaa, ns, mxr, txtr].some(x => x !== null);
    const meta = {
      confidence: !dnsOk ? { label: 'LOW CONFIDENCE', cls: 'warn' }
        : reg ? { label: 'HIGH CONFIDENCE', cls: 'success' }
        : { label: 'MEDIUM CONFIDENCE', cls: 'info' },
      sources: [
        { name: 'dns.google', ok: dnsOk },
        { name: 'RDAP', ok: !!reg },
        { name: 'InternetDB', ok: pivotIPs.length ? idbs.some(d => d !== null) : null },
      ],
    };
    out.innerHTML = `
      ${verdictBanner(v, signals, meta)}
      ${pivots('domain', domain)}
      <div class="intel-grid">
        ${card('Resolution', ips.length ? ips.slice(0, 6).map(i => `<div class="intel-kv"><b>IP</b><span class="mono">${esc(i)}</span></div>`).join('') : '<div class="intel-noev">does not resolve</div>')}
        ${card('Registration', regDate ? kv('Registered', esc(regDate)) + kv('Age', `${ageDays} days`) : '<div class="intel-noev">RDAP unavailable</div>')}
        ${card('Mail posture', (mx === null && txt === null) ? '<div class="intel-noev">unavailable</div>'
          : kv('MX', mx?.length ? esc(mx[0]) + (mx.length > 1 ? ` +${mx.length - 1}` : '') : 'none')
            + kv('SPF', (txt || []).some(r => /v=spf1/i.test(r)) ? 'present' : 'missing'))}
        ${card('Resolved-host exposure', pivotIPs.length
          ? pivotIPs.map((ip, i) => kv(esc(ip), idbs[i] && !idbs[i].__notFound ? `${(idbs[i].ports || []).length} ports · ${(idbs[i].vulns || []).length} CVEs` : 'no known exposure')).join('')
          : '<div class="intel-noev">no IPv4 to check</div>')}
        ${card('Name servers', (ns?.Answer || []).slice(0, 4).map(r => `<div class="intel-kv"><b>NS</b><span>${esc(r.data)}</span></div>`).join('') || '<div class="intel-noev">unavailable</div>')}
      </div>`;
  }

  function enrichHash(hash, out) {
    const kind = { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256' }[hash.length];
    out.innerHTML = `
      <div class="intel-verdict info">
        <div class="intel-verdict-head"><span class="alert-badge info">${kind} — NO KEYLESS SOURCE</span></div>
        <div class="intel-noev">Hash reputation feeds (VirusTotal, MalwareBazaar, CIRCL) all require API keys and block
        browser access — there is no honest way to check this client-side. Use the one-click pivots:</div>
      </div>
      ${pivots('hash', hash)}`;
  }

  // ── Bulk triage (multi-line IPs) ──────────────────
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  async function bulkTriage(ips, out) {
    out.innerHTML = `<div class="loading-row"><div class="spinner"></div><span>Triaging ${ips.length} IPs…</span></div>`;
    const rows = [];
    for (const ip of ips) {
      const [g, idb] = await Promise.all([geo(ip), internetdb(ip)]);
      const signals = ipSignals(idb, null, undefined);
      rows.push({ ip, g, idb, v: verdictFrom(signals) });
      await sleep(120); // gentle pacing
    }
    rows.sort((a, b) => b.v.score - a.v.score);
    out.innerHTML = `
      <div class="intel-bulk-head">${rows.length} IPs triaged — ranked by signal score. <span class="intel-caveat" style="display:inline">${CAVEAT}</span></div>
      <table class="ip-table"><thead><tr><th>IP</th><th>Verdict</th><th>Country</th><th>Ports</th><th>CVEs</th><th>Tags</th><th></th></tr></thead><tbody>
      ${rows.map(r => `<tr>
        <td class="mono">${esc(r.ip)}</td>
        <td><span class="alert-badge ${r.v.cls}">${r.v.label}</span></td>
        <td>${esc(r.g?.country || '—')}</td>
        <td class="mono">${(r.idb?.ports || []).length || '—'}</td>
        <td class="mono">${(r.idb?.vulns || []).length || '—'}</td>
        <td style="font-size:11px">${(r.idb?.tags || []).map(esc).join(', ') || '—'}</td>
        <td><button class="ioc-pivot" data-block-ip="${esc(r.ip)}">Block</button></td>
      </tr>`).join('')}</tbody></table>`;
  }

  // ── Lookup history (recent single-indicator lookups; localStorage) ──
  const HIST_KEY = 'sentinelx_intel_history';
  const loadHist = () => { try { return JSON.parse(localStorage.getItem(HIST_KEY)) || []; } catch { return []; } };
  function pushHist(type, value) {
    const h = [{ type, value, ts: Date.now() }, ...loadHist().filter(e => e.value !== value)].slice(0, 12);
    localStorage.setItem(HIST_KEY, JSON.stringify(h));
    renderHist();
  }
  function renderHist() {
    const el = document.getElementById('intel-history');
    if (!el) return;
    const h = loadHist();
    if (!h.length) { el.innerHTML = ''; el.style.display = 'none'; return; }
    el.style.display = 'flex';
    el.innerHTML = '<span style="font-size:11px;color:var(--text-3);align-self:center">Recent:</span>'
      + h.map(e => `<button class="ioc-pivot" data-hist="${esc(e.value)}" title="${esc(e.type)} — click to re-run">${esc(e.value.length > 28 ? e.value.slice(0, 26) + '…' : e.value)}</button>`).join('')
      + '<button class="ioc-pivot" data-hist-clear="1" title="Clear history" style="opacity:.7">Clear</button>';
  }

  // ── Controller ────────────────────────────────────
  async function run() {
    const input = document.getElementById('intel-input');
    const out = document.getElementById('intel-results');
    if (!input || !out) return;
    const lines = input.value.split('\n').map(s => s.trim()).filter(Boolean);
    if (!lines.length) return;

    const parsed = lines.map(detect).filter(Boolean);
    if (!parsed.length) { out.innerHTML = '<div class="intel-noev" style="padding:20px">No recognizable indicator (IP, domain, URL, or MD5/SHA-1/SHA-256 hash).</div>'; return; }

    const uniqIPs = [...new Set(parsed.filter(p => p.type === 'ip').map(p => p.value))];
    if (parsed.length > 1 && uniqIPs.length > 1) {
      return bulkTriage(uniqIPs.slice(0, 50), out); // ponytail: bulk = IPs only, cap 50
    }

    const { type, value } = parsed[0];
    pushHist(type, value);
    out.innerHTML = `<div class="loading-row"><div class="spinner"></div><span>Enriching ${esc(value)} across all sources…</span></div>`;
    if (type === 'ip') return enrichIP(value, out);
    if (type === 'domain') return enrichDomain(value, out);
    if (type === 'hash') return enrichHash(value, out);
  }

  // ── AI explanation of the current single-indicator evidence (shared window.AI) ──
  async function aiExplain() {
    if (!window.AI || !lastEvidence) return;
    const title = `AI Explanation — ${lastEvidence.value}`;
    if (!AI.requireKey()) return;
    AI.modal(title, '<div class="loading-row"><div class="spinner"></div><span>Explaining the evidence…</span></div>');
    try {
      const md = await AI.explainIntel(lastEvidence.kind, lastEvidence.value, lastEvidence.text);
      AI.modal(title, `<div class="ai-md">${AI.mdToHtml(md)}</div>`);
    } catch (err) {
      AI.modal(title, `<div style="color:var(--red)">${esc(err.message)}</div>`);
    }
  }

  function init() {
    document.getElementById('intel-run-btn')?.addEventListener('click', run);
    document.getElementById('intel-input')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) run();
    });
    document.getElementById('intel-results')?.addEventListener('click', (e) => {
      if (e.target.closest('#intel-explain')) aiExplain();
    });

    // Recent-lookups bar, inserted just above the results area.
    const results = document.getElementById('intel-results');
    if (results && !document.getElementById('intel-history')) {
      const bar = document.createElement('div');
      bar.id = 'intel-history';
      bar.setAttribute('style', 'display:none;flex-wrap:wrap;gap:6px;margin-bottom:10px');
      results.insertAdjacentElement('beforebegin', bar);
      bar.addEventListener('click', (e) => {
        if (e.target.closest('[data-hist-clear]')) { localStorage.removeItem(HIST_KEY); renderHist(); return; }
        const b = e.target.closest('[data-hist]');
        if (b) {
          const inp = document.getElementById('intel-input');
          if (inp) { inp.value = b.dataset.hist; run(); }
        }
      });
      renderHist();
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
