// ═══════════════════════════════════════════════════
//  ioc_extractor.js — pull indicators of compromise out
//  of any pasted text (threat reports, phishing emails,
//  log dumps). 100% client-side: regex over your input,
//  nothing is sent anywhere.
//
//  Handles "defanged" IOCs analysts share safely —
//  hxxp://, 1.2.3[.]4, evil[.]com, user[at]evil[.]com —
//  by refanging first, then can defang the output back
//  for safe copy/paste into a report.
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  // Refang: turn safe-shared IOCs back into real ones before matching
  function refang(t) {
    return t
      .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\s+dot\s+/gi, '.')
      .replace(/\[:\]|\[colon\]/gi, ':')
      .replace(/\[at\]|\(at\)|\s+at\s+/gi, '@')
      .replace(/\[\/\]/g, '/')
      .replace(/h(?:xx|XX|x|\[x\])p(s?)/gi, 'http$1')
      .replace(/\[\.]/g, '.');
  }

  // Defang for output — safe to paste into a ticket
  function defang(s) {
    return s
      .replace(/^http/i, 'hxxp')
      .replace(/\./g, '[.]')
      .replace(/@/g, '[at]')
      .replace(/:\/\//g, '[://]');
  }

  const RE = {
    url:    /\bhttps?:\/\/[^\s<>"'`\]\)]+/gi,
    email:  /\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi,
    ipv4:   /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi,
    md5:    /\b[a-f0-9]{32}\b/gi,
    sha1:   /\b[a-f0-9]{40}\b/gi,
    sha256: /\b[a-f0-9]{64}\b/gi,
    cve:    /\bCVE-\d{4}-\d{4,7}\b/gi,
  };

  const uniq = (arr) => [...new Set(arr)];
  const isPrivate = (ip) => /^(?:10|127)\./.test(ip) || /^192\.168\./.test(ip) ||
    /^169\.254\./.test(ip) || /^172\.(?:1[6-9]|2\d|3[01])\./.test(ip) || /^0\./.test(ip);

  function extract(raw) {
    const text = refang(raw);

    const urls   = uniq(text.match(RE.url) || []);
    const emails = uniq((text.match(RE.email) || []).map(s => s.toLowerCase()));
    const cves   = uniq((text.match(RE.cve) || []).map(s => s.toUpperCase()));
    // Hashes: longest first so a SHA-256 isn't also counted as MD5+SHA1 fragments
    const sha256 = uniq((text.match(RE.sha256) || []).map(s => s.toLowerCase()));
    let rest = text; sha256.forEach(h => { rest = rest.replaceAll(h, ' '); });
    const sha1   = uniq((rest.match(RE.sha1) || []).map(s => s.toLowerCase()));
    sha1.forEach(h => { rest = rest.replaceAll(h, ' '); });
    const md5    = uniq((rest.match(RE.md5) || []).map(s => s.toLowerCase()));

    // Mask URLs + emails so bare domains/IPs aren't double-counted from them
    let masked = text.replace(RE.url, ' ').replace(RE.email, ' ');
    const ipv4 = uniq(masked.match(RE.ipv4) || []);
    // Domains: drop anything that's actually an IP, and TLD-only noise.
    // Anchored, non-global regex — .test() on a /g regex is stateful (lastIndex).
    const isIP = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    const domains = uniq((masked.match(RE.domain) || [])
      .map(s => s.toLowerCase())
      .filter(d => !isIP.test(d) && d.includes('.')));

    return { urls, domains, ipv4, emails, md5, sha1, sha256, cves };
  }

  // Which tool each IOC type can pivot into
  const PIVOTS = {
    ipv4:   [['ips', 'ip-input', 'lookup-btn', 'Lookup'], ['asn', 'asn-input', 'asn-lookup-btn', 'ASN'], ['abuseipdb', 'abuse-ip-input', null, 'Abuse']],
    domain: [['dns', 'dns-input', 'dns-lookup-btn', 'DNS'], ['whois', 'whois-input', 'whois-lookup-btn', 'WHOIS'], ['ssl', 'ssl-domain-input', 'ssl-lookup-btn', 'Certs']],
    cve:    [],
  };

  function pivot(page, inputId, btnId, value) {
    navigateTo(page);
    setTimeout(() => {
      const inp = document.getElementById(inputId);
      if (inp) inp.value = value;
      if (btnId) document.getElementById(btnId)?.click();
      else inp?.focus();
    }, 80);
  }
  window.__iocPivot = pivot;

  const GROUPS = [
    { key: 'ipv4',   label: 'IPv4 Addresses', dot: 'red',    pivot: 'ipv4' },
    { key: 'domains',label: 'Domains',        dot: 'amber',  pivot: 'domain' },
    { key: 'urls',   label: 'URLs',           dot: 'amber',  pivot: null },
    { key: 'emails', label: 'Emails',         dot: 'cyan',   pivot: null },
    { key: 'sha256', label: 'SHA-256',        dot: 'purple', pivot: null },
    { key: 'sha1',   label: 'SHA-1',          dot: 'purple', pivot: null },
    { key: 'md5',    label: 'MD5',            dot: 'purple', pivot: null },
    { key: 'cves',   label: 'CVEs',           dot: 'red',    pivot: 'cve' },
  ];

  function esc(s) { return s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

  function render(iocs) {
    const wrap = document.getElementById('ioc-results');
    const empty = document.getElementById('ioc-empty');
    const statsEl = document.getElementById('ioc-stats');
    const doDefang = document.getElementById('ioc-defang-toggle')?.checked;

    const total = Object.values(iocs).reduce((n, a) => n + a.length, 0);
    if (!total) {
      wrap.innerHTML = '';
      empty.style.display = '';
      empty.textContent = 'No indicators found in that text.';
      statsEl.textContent = '';
      return;
    }
    empty.style.display = 'none';
    statsEl.textContent = `${total} indicator${total === 1 ? '' : 's'}`;

    wrap.innerHTML = GROUPS.filter(g => iocs[g.key].length).map(g => {
      const rows = iocs[g.key].map(v => {
        const shown = doDefang ? defang(v) : v;
        const priv = g.key === 'ipv4' && isPrivate(v);
        const pivots = (PIVOTS[g.pivot] || []).map(([page, inp, btn, lbl]) =>
          `<button class="ioc-pivot" data-pivot-page="${page}" data-pivot-input="${inp}"${btn ? ` data-pivot-btn="${btn}"` : ''} data-pivot-val="${esc(v)}">${lbl}</button>`
        ).join('');
        return `<div class="ioc-row">
          <span class="ioc-val${priv ? ' ioc-priv' : ''}" title="${priv ? 'Private / reserved range' : ''}">${esc(shown)}</span>
          <div class="ioc-actions">
            ${pivots}
            <button class="ioc-copy" data-copy="${esc(shown)}">Copy</button>
          </div>
        </div>`;
      }).join('');
      return `<div class="ioc-group">
        <div class="ioc-group-head"><span class="idot ${g.dot}"></span>${g.label}<span class="ioc-count">${iocs[g.key].length}</span></div>
        ${rows}
      </div>`;
    }).join('');
  }

  let last = null;
  function run() {
    const raw = document.getElementById('ioc-input').value;
    if (!raw.trim()) { document.getElementById('ioc-input').focus(); return; }
    last = extract(raw);
    render(last);
    document.getElementById('ioc-copyall-btn').style.display = '';
  }

  const SAMPLE = `Incident IR-2287 — phishing wave, 2026-07-05

Sender: billing[at]paypa1-secure[.]com  (spoofed)
Landing page: hxxps://paypa1-secure[.]com/login.php
C2 beacon observed to 45[.]33[.]32[.]156 and 185.220.101.5
Internal jump host 10.0.4.12 was contacted.

Dropper: invoice.pdf.exe
  MD5    44d88612fea8a8f36de82e1278abb02f
  SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Exploited: CVE-2024-3400 (firewall), also referenced CVE-2021-44228.
Refs: https://nvd.nist.gov/vuln/detail/CVE-2024-3400`;

  document.addEventListener('DOMContentLoaded', () => {
    if (!document.getElementById('ioc-input')) return;
    document.getElementById('ioc-extract-btn')?.addEventListener('click', run);
    document.getElementById('ioc-sample-btn')?.addEventListener('click', () => {
      document.getElementById('ioc-input').value = SAMPLE; run();
    });
    document.getElementById('ioc-clear-btn')?.addEventListener('click', () => {
      document.getElementById('ioc-input').value = '';
      document.getElementById('ioc-results').innerHTML = '';
      document.getElementById('ioc-empty').style.display = '';
      document.getElementById('ioc-empty').textContent = 'Paste text above and hit Extract.';
      document.getElementById('ioc-stats').textContent = '';
      document.getElementById('ioc-copyall-btn').style.display = 'none';
    });
    document.getElementById('ioc-defang-toggle')?.addEventListener('change', () => { if (last) render(last); });
    document.getElementById('ioc-copyall-btn')?.addEventListener('click', () => {
      if (!last) return;
      const doDefang = document.getElementById('ioc-defang-toggle')?.checked;
      const lines = [];
      GROUPS.filter(g => last[g.key].length).forEach(g => {
        lines.push(`# ${g.label}`);
        last[g.key].forEach(v => lines.push(doDefang ? defang(v) : v));
        lines.push('');
      });
      navigator.clipboard.writeText(lines.join('\n').trim())
        .then(() => showToast('All indicators copied', 'success'));
    });
  });
})();
