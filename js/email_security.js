// ═══════════════════════════════════════════════════
//  email_security.js — SPF / DMARC / DKIM / MX / DNSSEC audit
//  Live DNS via Google DNS-over-HTTPS (keyless, CORS-open).
//  Every finding is derived from the actual DNS answers — the grade is a
//  formula over live results, never canned.
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  const DOH = 'https://dns.google/resolve';
  // Selectors commonly used by major providers — we probe these for DKIM keys.
  const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 's1', 's2', 'mail', 'smtp', 'dkim', 'pm', 'zoho', 'mandrill'];

  const $ = (id) => document.getElementById(id);

  async function dns(name, type) {
    const res = await fetch(`${DOH}?name=${encodeURIComponent(name)}&type=${type}`);
    if (!res.ok) throw new Error('DNS query failed (' + res.status + ')');
    return res.json();
  }

  const txtRecords = (resp) =>
    (resp.Answer || [])
      .filter((a) => a.type === 16)
      .map((a) => a.data.replace(/^"|"$/g, '').replace(/"\s+"/g, ''));

  // ── Individual checks (each returns {status, title, detail, record?}) ──
  async function checkMX(domain) {
    const r = await dns(domain, 'MX');
    const mx = (r.Answer || []).filter((a) => a.type === 15).map((a) => a.data);
    if (mx.length === 0) return { status: 'warn', title: 'MX records', detail: 'No MX records — this domain does not receive mail. SPF/DMARC still matter to stop spoofing of outbound mail.' };
    if (mx.length === 1 && /^0 \.?$/.test(mx[0])) return { status: 'pass', title: 'MX records', detail: 'Null MX (RFC 7505) — explicitly declares the domain sends/receives no mail.' };
    return { status: 'pass', title: 'MX records', detail: `${mx.length} mail server${mx.length > 1 ? 's' : ''} configured.`, record: mx.slice(0, 4).join('  ·  ') };
  }

  async function checkSPF(domain) {
    const r = await dns(domain, 'TXT');
    const spf = txtRecords(r).filter((t) => /^v=spf1( |$)/i.test(t));
    if (spf.length === 0) return { status: 'fail', title: 'SPF', detail: 'No SPF record. Anyone can send mail claiming to be this domain and receivers have no way to check the source.' };
    if (spf.length > 1) return { status: 'fail', title: 'SPF', detail: `${spf.length} SPF records found — multiple records are a permanent error (permerror); receivers ignore SPF entirely.`, record: spf.join(' | ') };
    const rec = spf[0];
    const all = rec.match(/([-~?+]?)all\b/);
    const qualifier = all ? (all[1] || '+') : null;
    let status, detail;
    if (!qualifier) { status = 'warn'; detail = 'SPF record has no "all" mechanism — unmatched senders are neutral by default, which weakens enforcement.'; }
    else if (qualifier === '-') { status = 'pass'; detail = 'Strict SPF (-all): mail from unauthorized servers is rejected.'; }
    else if (qualifier === '~') { status = 'pass'; detail = 'Soft-fail SPF (~all): unauthorized mail is marked suspicious. Fine when paired with DMARC.'; }
    else if (qualifier === '?') { status = 'warn'; detail = 'Neutral SPF (?all): receivers are told to treat unauthorized senders as unknown — effectively no protection.'; }
    else { status = 'fail'; detail = 'SPF ends in +all: it explicitly authorizes EVERY server on the internet to send as this domain.'; }
    const lookups = (rec.match(/\b(include:|a[: ]|mx[: ]|ptr|exists:|redirect=)/g) || []).length;
    if (lookups > 10) detail += ` Note: ~${lookups} DNS-lookup mechanisms — over the limit of 10, which causes permerror.`;
    return { status, title: 'SPF', detail, record: rec };
  }

  async function checkDMARC(domain) {
    const r = await dns(`_dmarc.${domain}`, 'TXT');
    const rec = txtRecords(r).find((t) => /^v=DMARC1/i.test(t));
    if (!rec) return { status: 'fail', title: 'DMARC', detail: 'No DMARC record. Even with SPF/DKIM, receivers have no policy for failing mail and the domain gets no abuse reports.' };
    const p = (rec.match(/;\s*p=(\w+)/i) || [])[1]?.toLowerCase();
    const pct = (rec.match(/;\s*pct=(\d+)/i) || [])[1];
    const rua = /;\s*rua=/i.test(rec);
    let status, detail;
    if (p === 'reject') { status = 'pass'; detail = 'Policy p=reject — spoofed mail is refused outright. The strongest setting.'; }
    else if (p === 'quarantine') { status = 'pass'; detail = 'Policy p=quarantine — spoofed mail goes to spam. Good; p=reject is stronger.'; }
    else if (p === 'none') { status = 'warn'; detail = 'Policy p=none — failures are only reported, never acted on. Fine for rollout, weak long-term.'; }
    else { status = 'warn'; detail = 'DMARC record present but the policy tag could not be parsed.'; }
    if (pct && +pct < 100) detail += ` Applies to only ${pct}% of mail (pct=${pct}).`;
    if (!rua) detail += ' No rua= address — the domain receives no aggregate reports.';
    return { status, title: 'DMARC', detail, record: rec };
  }

  async function checkDKIM(domain) {
    // Probe common selectors in parallel; found = TXT with a DKIM key tag.
    const probes = await Promise.allSettled(
      DKIM_SELECTORS.map(async (sel) => {
        const r = await dns(`${sel}._domainkey.${domain}`, 'TXT');
        const rec = txtRecords(r).find((t) => /v=DKIM1|k=rsa|p=[A-Za-z0-9+/]/.test(t));
        return rec ? { sel, empty: /(^|;)\s*p=\s*(;|$)/.test(rec) } : null;
      })
    );
    const found = probes.filter((p) => p.status === 'fulfilled' && p.value).map((p) => p.value);
    if (found.length === 0) return { status: 'warn', title: 'DKIM', detail: `No keys at ${DKIM_SELECTORS.length} common selectors. DKIM may still exist under a custom selector — it is only discoverable by name.` };
    const active = found.filter((f) => !f.empty);
    if (active.length === 0) return { status: 'warn', title: 'DKIM', detail: 'Selector(s) found but the key is revoked (empty p=).', record: found.map((f) => f.sel).join(', ') };
    return { status: 'pass', title: 'DKIM', detail: `Signing key${active.length > 1 ? 's' : ''} published at selector${active.length > 1 ? 's' : ''}: ${active.map((f) => f.sel).join(', ')}.` };
  }

  async function checkDNSSEC(domain) {
    const r = await dns(domain, 'SOA');
    // dns.google sets AD=true only when the full chain validates.
    return r.AD
      ? { status: 'pass', title: 'DNSSEC', detail: 'Responses are cryptographically signed and validated — DNS answers for this domain cannot be silently forged.' }
      : { status: 'warn', title: 'DNSSEC', detail: 'Not validated. DNS answers (including MX and the SPF/DMARC records above) are not cryptographically protected.' };
  }

  // ── Grade: formula over the live findings ─────────
  function grade(results) {
    const score = results.reduce((n, r) => n + (r.status === 'pass' ? 2 : r.status === 'warn' ? 1 : 0), 0);
    const max = results.length * 2;
    const pct = score / max;
    if (pct >= 0.9) return { label: 'Strong', cls: 'success' };
    if (pct >= 0.6) return { label: 'Moderate', cls: 'warn' };
    return { label: 'Weak', cls: 'danger' };
  }

  // ── Render ────────────────────────────────────────
  const ICONS = { pass: '✓', warn: '!', fail: '✕' };
  function render(results) {
    $('email-results').innerHTML = results.map((r) => `
      <div class="finding-row">
        <span class="finding-icon ${r.status}">${ICONS[r.status]}</span>
        <div class="finding-body">
          <span class="finding-title">${r.title}</span>
          <span class="finding-detail">${r.detail}</span>
          ${r.record ? `<code class="finding-record">${r.record.replace(/</g, '&lt;')}</code>` : ''}
        </div>
      </div>
    `).join('');
    const g = grade(results);
    const badge = $('email-grade');
    badge.textContent = g.label;
    badge.className = 'alert-badge ' + g.cls;
  }

  // ── Run ───────────────────────────────────────────
  async function run() {
    const domain = $('email-domain-input').value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    const errEl = $('email-error');
    errEl.style.display = 'none';
    $('email-results-panel').style.display = 'none';
    if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) {
      $('email-error-msg').textContent = 'Enter a valid domain, e.g. example.com';
      errEl.style.display = 'block';
      return;
    }
    $('email-loading').style.display = 'flex';
    try {
      const results = await Promise.all([
        checkSPF(domain), checkDMARC(domain), checkDKIM(domain), checkMX(domain), checkDNSSEC(domain),
      ]);
      render(results);
      $('email-results-panel').style.display = 'flex';
    } catch (err) {
      $('email-error-msg').textContent = 'DNS lookup failed: ' + (err?.message || 'network error');
      errEl.style.display = 'block';
    } finally {
      $('email-loading').style.display = 'none';
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    $('email-check-btn')?.addEventListener('click', run);
    $('email-domain-input')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); });
    document.querySelectorAll('.quick-email-domain').forEach((b) =>
      b.addEventListener('click', () => { $('email-domain-input').value = b.dataset.domain; run(); })
    );
  });
})();
