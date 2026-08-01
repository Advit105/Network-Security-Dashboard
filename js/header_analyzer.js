// ═══════════════════════════════════════════════════
//  header_analyzer.js — Email header forensics
//  Paste raw headers → parsed Received: route, auth
//  results (SPF/DKIM/DMARC) with alignment checks, and
//  spoofing red flags. The #1 phishing-triage task.
//  100% client-side — headers never leave the browser.
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ── parsing ───────────────────────────────────────
  // RFC 5322: headers end at the first blank line; a line starting
  // with whitespace continues ("folds into") the previous header.
  function parseHeaders(raw) {
    const headerBlock = raw.split(/\r?\n\r?\n/)[0];
    const lines = headerBlock.split(/\r?\n/);
    const headers = [];
    for (const line of lines) {
      if (/^[ \t]/.test(line) && headers.length) {
        headers[headers.length - 1].value += ' ' + line.trim();
      } else {
        const m = line.match(/^([\w-]+):\s*(.*)$/);
        if (m) headers.push({ name: m[1], value: m[2] });
      }
    }
    return headers;
  }

  const get = (headers, name) => headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value || null;
  const getAll = (headers, name) => headers.filter((h) => h.name.toLowerCase() === name.toLowerCase()).map((h) => h.value);

  const addrOf = (v) => v?.match(/<([^>]+)>/)?.[1] || v?.match(/[\w.+-]+@[\w.-]+/)?.[0] || null;
  const domainOf = (addr) => addr?.split('@')[1]?.toLowerCase().replace(/[>;,\s].*$/, '') || null;
  // Relaxed alignment: exact match or organizational-domain suffix
  // (mail.example.com aligns with example.com)
  const aligned = (a, b) => !!a && !!b && (a === b || a.endsWith('.' + b) || b.endsWith('.' + a));

  const PRIVATE_IP = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80:|::1|fc|fd)/i;

  function parseReceived(value) {
    const hop = { raw: value, from: null, by: null, ip: null, proto: null, date: null };
    hop.from = value.match(/^from\s+([^\s(]+)/i)?.[1] || null;
    hop.by = value.match(/\bby\s+([^\s(;]+)/i)?.[1] || null;
    hop.proto = value.match(/\bwith\s+([A-Za-z0-9+._-]+)/i)?.[1] || null;
    // IPs in the "from …" clause (before "by"); a hop often lists the
    // sender's LAN address first (from [192.168.x.x] (helo [public])),
    // so prefer the first PUBLIC address in the clause
    const fromClause = value.split(/\bby\b/i)[0];
    const ips = [
      ...(fromClause.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || []),
      ...(fromClause.match(/\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/gi) || []),
    ];
    hop.ip = ips.find((ip) => !PRIVATE_IP.test(ip)) || ips[0] || null;
    const dateStr = value.split(';').pop().trim();
    const d = new Date(dateStr);
    if (!isNaN(d)) hop.date = d;
    return hop;
  }

  // Authentication-Results: pull result + key domain for each method
  function parseAuth(headers) {
    const blob = getAll(headers, 'Authentication-Results').join(' ; ') + ' ' + (get(headers, 'Received-SPF') || '');
    const grab = (re) => blob.match(re)?.[1]?.toLowerCase() || null;
    return {
      present: /spf=|dkim=|dmarc=/i.test(blob),
      spf:   grab(/\bspf=(\w+)/i),
      spfDomain: grab(/smtp\.mailfrom=(?:[\w.+-]+@)?([\w.-]+)/i),
      dkim:  grab(/\bdkim=(\w+)/i),
      dkimDomain: grab(/header\.d=([\w.-]+)/i),
      dmarc: grab(/\bdmarc=(\w+)/i),
      dmarcPolicy: grab(/\bp=(\w+)/i),
    };
  }

  // ── analysis → findings ───────────────────────────
  function analyze(headers) {
    const fromAddr = addrOf(get(headers, 'From'));
    const fromDom  = domainOf(fromAddr);
    const replyAddr = addrOf(get(headers, 'Reply-To'));
    const returnAddr = addrOf(get(headers, 'Return-Path'));
    const msgIdDom = domainOf(get(headers, 'Message-ID'));
    const auth = parseAuth(headers);

    // Received headers stack newest-first; reverse → origin first
    const hops = getAll(headers, 'Received').map(parseReceived).reverse();
    hops.forEach((h, i) => {
      h.delay = i > 0 && h.date && hops[i - 1].date ? Math.round((h.date - hops[i - 1].date) / 1000) : null;
    });
    const originIp = hops.map((h) => h.ip).find((ip) => ip && !PRIVATE_IP.test(ip)) || null;

    const flags = [];  // { sev: 'danger'|'warn'|'info', text }
    const f = (sev, text) => flags.push({ sev, text });

    if (replyAddr && fromDom && !aligned(domainOf(replyAddr), fromDom))
      f('danger', `Reply-To (${domainOf(replyAddr)}) differs from From (${fromDom}) — replies go somewhere else. Classic phishing pattern.`);
    if (auth.spf && ['fail', 'softfail', 'permerror'].includes(auth.spf))
      f('danger', `SPF ${auth.spf} — the sending server was not authorized for ${auth.spfDomain || 'the envelope domain'}.`);
    if (auth.dkim === 'fail') f('danger', 'DKIM signature failed verification — content altered or signature forged.');
    if (auth.dmarc === 'fail') f('danger', 'DMARC failed — the From: domain\'s policy rejects this message\'s authentication.');
    if (auth.present && !auth.dmarc) f('warn', 'No DMARC evaluation recorded.');
    if (!auth.present) f('warn', 'No Authentication-Results header — this copy carries no SPF/DKIM/DMARC verdict (common when pasting from a sent/internal copy).');
    if (auth.dkim === 'pass' && auth.dkimDomain && fromDom && !aligned(auth.dkimDomain, fromDom))
      f('warn', `DKIM passes but signs for ${auth.dkimDomain}, not the From: domain ${fromDom} — unaligned signature (bulk sender or spoof).`);
    if (auth.spf === 'pass' && auth.spfDomain && fromDom && !aligned(auth.spfDomain, fromDom))
      f('warn', `SPF passes for ${auth.spfDomain}, but From: claims ${fromDom} — envelope/header mismatch.`);
    if (returnAddr && fromDom && !aligned(domainOf(returnAddr), fromDom))
      f('info', `Return-Path (${domainOf(returnAddr)}) ≠ From domain — normal for mailing lists/ESPs, notable otherwise.`);
    if (msgIdDom && fromDom && !aligned(msgIdDom, fromDom))
      f('info', `Message-ID domain (${msgIdDom}) ≠ From domain — weak signal, common with ESPs.`);

    const hdrDate = new Date(get(headers, 'Date'));
    if (!isNaN(hdrDate) && hops[0]?.date && Math.abs(hops[0].date - hdrDate) > 10 * 60 * 1000)
      f('warn', `Date: header is ${Math.round(Math.abs(hops[0].date - hdrDate) / 60000)} min off the first relay timestamp — possible forged Date.`);
    hops.forEach((h, i) => {
      if (h.delay !== null && h.delay > 300)
        f('info', `Hop ${i + 1} sat ${Math.round(h.delay / 60)} min at ${h.by || 'a relay'} — queuing delay or greylisting.`);
      if (h.delay !== null && h.delay < -30)
        f('warn', `Hop ${i + 1} timestamp goes backwards ${-h.delay}s — clock skew or a forged Received line.`);
    });

    const xMailer = get(headers, 'X-Mailer') || get(headers, 'User-Agent');
    const danger = flags.filter((x) => x.sev === 'danger').length;
    const warn = flags.filter((x) => x.sev === 'warn').length;
    const verdict = danger ? { label: 'HIGH RISK', cls: 'danger' }
                  : warn   ? { label: 'SUSPICIOUS', cls: 'warn' }
                  : { label: 'NO RED FLAGS', cls: 'success' };

    return { headers, fromAddr, fromDom, replyAddr, returnAddr, auth, hops, originIp, flags, verdict, xMailer,
             subject: get(headers, 'Subject'), to: get(headers, 'To'), date: get(headers, 'Date'), msgId: get(headers, 'Message-ID') };
  }

  // ── rendering ─────────────────────────────────────
  const authBadge = (v) => {
    if (!v) return '<span class="hdr-auth none">—</span>';
    const cls = v === 'pass' ? 'pass' : ['fail', 'permerror'].includes(v) ? 'fail' : 'soft';
    return `<span class="hdr-auth ${cls}">${esc(v.toUpperCase())}</span>`;
  };

  function render(r) {
    const summary = document.getElementById('hdr-summary');
    const flagsEl = document.getElementById('hdr-flags');
    const hopsEl = document.getElementById('hdr-hops');
    const verdictEl = document.getElementById('hdr-verdict');

    verdictEl.className = `alert-badge ${r.verdict.cls}`;
    verdictEl.textContent = r.verdict.label;

    summary.innerHTML = `
      <div class="hdr-kv"><b>From</b><span>${esc(r.fromAddr || '—')}</span></div>
      ${r.replyAddr ? `<div class="hdr-kv"><b>Reply-To</b><span>${esc(r.replyAddr)}</span></div>` : ''}
      ${r.returnAddr ? `<div class="hdr-kv"><b>Return-Path</b><span>${esc(r.returnAddr)}</span></div>` : ''}
      <div class="hdr-kv"><b>To</b><span>${esc(r.to || '—')}</span></div>
      <div class="hdr-kv"><b>Subject</b><span>${esc(r.subject || '—')}</span></div>
      <div class="hdr-kv"><b>Date</b><span>${esc(r.date || '—')}</span></div>
      ${r.xMailer ? `<div class="hdr-kv"><b>Mailer</b><span>${esc(r.xMailer)}</span></div>` : ''}
      <div class="hdr-kv"><b>SPF</b><span>${authBadge(r.auth.spf)} ${esc(r.auth.spfDomain || '')}</span></div>
      <div class="hdr-kv"><b>DKIM</b><span>${authBadge(r.auth.dkim)} ${r.auth.dkimDomain ? 'd=' + esc(r.auth.dkimDomain) : ''}</span></div>
      <div class="hdr-kv"><b>DMARC</b><span>${authBadge(r.auth.dmarc)} ${r.auth.dmarcPolicy ? 'p=' + esc(r.auth.dmarcPolicy) : ''}</span></div>
      ${r.originIp ? `
      <div class="hdr-kv"><b>Origin IP</b><span class="mono">${esc(r.originIp)}
        <button class="ioc-pivot" data-pivot-page="ips" data-pivot-input="ip-input" data-pivot-btn="lookup-btn" data-pivot-val="${esc(r.originIp)}">Lookup</button>
        <button class="ioc-pivot" data-pivot-page="abuseipdb" data-pivot-input="abuse-ip-input" data-pivot-val="${esc(r.originIp)}">Abuse</button>
        <button class="ioc-pivot" data-pivot-page="asn" data-pivot-input="asn-input" data-pivot-btn="asn-lookup-btn" data-pivot-val="${esc(r.originIp)}">ASN</button>
      </span></div>` : ''}`;

    flagsEl.innerHTML = r.flags.length
      ? r.flags.map((x) => `<div class="hdr-flag ${x.sev}"><span class="hdr-flag-dot"></span>${esc(x.text)}</div>`).join('')
      : '<div class="hdr-flag success"><span class="hdr-flag-dot"></span>Nothing suspicious found in the headers themselves — still verify links and attachments.</div>';

    hopsEl.innerHTML = r.hops.length
      ? r.hops.map((h, i) => `
        <div class="hdr-hop">
          <div class="hdr-hop-num">${i + 1}</div>
          <div class="hdr-hop-body">
            <div class="hdr-hop-route">
              <span>${esc(h.from || 'unknown')}</span>
              ${h.ip ? `<span class="mono hdr-hop-ip${PRIVATE_IP.test(h.ip) ? ' private' : ''}">${esc(h.ip)}</span>` : ''}
              <span class="hdr-hop-arrow">→</span>
              <span>${esc(h.by || 'unknown')}</span>
              ${h.proto ? `<span class="hdr-hop-proto">${esc(h.proto)}</span>` : ''}
            </div>
            <div class="hdr-hop-meta">
              ${h.date ? h.date.toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC') : 'no timestamp'}
              ${h.delay !== null ? ` · +${h.delay}s` : ''}
            </div>
          </div>
        </div>`).join('')
      : '<div style="color:var(--text-3);font-size:12.5px">No Received: headers found — paste the full raw header block ("Show original" in Gmail, "View source" in Outlook).</div>';

    document.getElementById('hdr-results').style.display = '';
  }

  // ── sample (synthetic, for demo — user-triggered) ──
  const SAMPLE = `Return-Path: <bounce@mail-blast-esp.net>
Received: from mx.victim-corp.example (mx.victim-corp.example [203.0.113.10])
\tby inbox.victim-corp.example with ESMTPS id 8xKq2;
\tThu, 9 Jul 2026 14:22:31 +0000
Received: from relay7.mail-blast-esp.net (relay7.mail-blast-esp.net [198.51.100.77])
\tby mx.victim-corp.example with ESMTPS;
\tThu, 9 Jul 2026 14:22:29 +0000
Received: from [192.168.1.44] (unknown [185.220.101.5])
\tby relay7.mail-blast-esp.net with ESMTPA id 99Zt;
\tThu, 9 Jul 2026 14:22:11 +0000
Authentication-Results: mx.victim-corp.example;
\tspf=pass (sender IP is 198.51.100.77) smtp.mailfrom=mail-blast-esp.net;
\tdkim=pass header.d=mail-blast-esp.net;
\tdmarc=none header.from=paypa1-support.example
From: "PayPal Support" <security@paypa1-support.example>
Reply-To: <recovery.desk.9921@webmail-free.example>
To: victim@victim-corp.example
Subject: Your account has been limited - verify now
Date: Thu, 9 Jul 2026 11:02:00 +0000
Message-ID: <20260709.99zt@relay7.mail-blast-esp.net>
X-Mailer: BulkSenderPro 2.4
Content-Type: text/html; charset=utf-8`;

  // ── wiring ────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('hdr-input');
    const btn = document.getElementById('hdr-analyze-btn');
    if (!input || !btn) return;

    function go() {
      const raw = input.value;
      if (!raw.trim()) return;
      const headers = parseHeaders(raw);
      if (!headers.length) {
        window.showToast?.('Could not find any "Name: value" header lines', 'danger');
        return;
      }
      render(analyze(headers));
    }

    btn.addEventListener('click', go);
    document.getElementById('hdr-sample-btn')?.addEventListener('click', () => { input.value = SAMPLE; go(); });
    document.getElementById('hdr-clear-btn')?.addEventListener('click', () => {
      input.value = '';
      document.getElementById('hdr-results').style.display = 'none';
    });
  });
})();
