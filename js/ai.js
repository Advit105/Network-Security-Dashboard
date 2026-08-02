// ═══════════════════════════════════════════════════
//  ai.js — shared Claude (Anthropic) client for SentinelX.
//  Bring-your-own-key, stored in localStorage (same pattern as
//  abuseipdb.js), sent straight to the Anthropic API from the browser.
//  window.AI is reused by every AI feature (case summary first;
//  intel + log triage later). No inline handlers (CSP-safe).
//
//  Node self-check for the pure escaping/markdown logic:  node js/ai.js
// ═══════════════════════════════════════════════════
(function () {
  'use strict';

  const MODEL = 'claude-opus-4-8';           // ponytail: default per house rule; swap here if desired
  const KEY = 'sentinelx_anthropic_key';

  // ── Pure helpers (defined first so the Node self-check can reach them) ──
  const escapeHtml = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // Tiny markdown → safe HTML. Escapes first, then whitelists a few marks —
  // the model output is untrusted, so nothing it emits can inject HTML.
  function mdToHtml(md) {
    const inline = (s) => s
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+?)`/g, '<code>$1</code>');
    let html = '', inList = false;
    for (const raw of escapeHtml(md).split('\n')) {
      const line = raw.trimEnd();
      const h = line.match(/^(#{1,4})\s+(.*)/);
      const b = line.match(/^[-*]\s+(.*)/);
      if (h) {
        if (inList) { html += '</ul>'; inList = false; }
        const lvl = Math.min(h[1].length + 1, 6);   // downshift: ## → <h3>
        html += `<h${lvl}>${inline(h[2])}</h${lvl}>`;
      } else if (b) {
        if (!inList) { html += '<ul>'; inList = true; }
        html += `<li>${inline(b[1])}</li>`;
      } else if (!line.trim()) {
        if (inList) { html += '</ul>'; inList = false; }
      } else {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<p>${inline(line)}</p>`;
      }
    }
    if (inList) html += '</ul>';
    return html;
  }

  const isBrowser = typeof window !== 'undefined';

  if (isBrowser) {
    const getKey = () => localStorage.getItem(KEY) || '';
    const setKey = (v) => v ? localStorage.setItem(KEY, v) : localStorage.removeItem(KEY);
    const hasKey = () => getKey().length > 10;

    // Gate for every AI action: true if a key is set, else nudge to Settings → AI.
    function requireKey() {
      if (hasKey()) return true;
      (window.showToast || (() => {}))('Add your Claude API key in Settings → AI Assistant to use AI features', 'warn');
      if (typeof navigateTo === 'function') navigateTo('settings');
      const input = document.getElementById('ai-apikey');
      if (input) { input.focus(); input.scrollIntoView({ block: 'center', behavior: 'smooth' }); }
      return false;
    }

    // ── One Claude call. Non-streaming, bounded output → no HTTP timeout. ──
    async function complete(system, userText, maxTokens = 2048) {
      const key = getKey();
      if (!key) throw new Error('No Claude API key set. Add one in Settings → AI Assistant.');
      let res;
      try {
        res = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-api-key': key,
            'anthropic-version': '2023-06-01',
            // Anthropic blocks browser calls unless this opt-in header is present.
            'anthropic-dangerous-direct-browser-access': 'true',
          },
          body: JSON.stringify({
            model: MODEL,
            max_tokens: maxTokens,
            system,
            messages: [{ role: 'user', content: userText }],
          }),
        });
      } catch {
        throw new Error('Could not reach the Anthropic API (network or CORS).');
      }
      if (res.status === 401) throw new Error('Invalid API key — check it in Settings → AI Assistant.');
      if (res.status === 429) throw new Error('Rate limited by Anthropic — wait a moment and retry.');
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error(e.error?.message || `Claude API error (${res.status}).`);
      }
      const data = await res.json();
      const text = (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('').trim();
      if (!text) throw new Error('Claude returned an empty response.');
      return text;
    }

    // ── Case → incident report. Grounded strictly in the provided case. ──
    function summarizeCase(c) {
      const items = (c.items || []).map(it => it.value);
      const system =
        'You are a senior SOC analyst. From the indicators and notes of an investigation ' +
        'case, write a concise incident report in markdown with these sections: ' +
        '**Summary** (2–3 sentences), **Severity** (one of INFO/LOW/MEDIUM/HIGH/CRITICAL with a ' +
        'one-line justification), **Key Indicators** (bullet the notable IPs/domains/hashes and what ' +
        'stands out), **Likely Activity** (what the evidence suggests), and **Recommended Actions** ' +
        '(concrete, bulleted). Base every claim only on the data provided. If the evidence is thin, ' +
        'say so plainly. Never invent indicators or findings.';
      const user =
        `Case name: ${c.name || 'Untitled'}\n\n` +
        `Indicators (${items.length}):\n${items.map(v => '- ' + v).join('\n') || '(none)'}\n\n` +
        `Analyst notes:\n${c.notes || '(none)'}`;
      return complete(system, user, 2048);
    }

    // ── Threat-intel indicator → plain-English analyst explanation ──
    function explainIntel(kind, value, evidenceText) {
      const system =
        'You are a senior SOC analyst. You are given the evidence SentinelX gathered on a single ' +
        'indicator from keyless exposure sources (geolocation, Shodan InternetDB, DNS, RDAP, RIPE, Tor). ' +
        'Explain in plain English, in markdown, with these sections: **Assessment** (one paragraph — benign / ' +
        'worth watching / suspicious, and why), **What stands out** (bullets tying each point back to the ' +
        'evidence), and **Next steps** (concrete, bulleted, including which reputation feed to pivot to). ' +
        'This is exposure-based, NOT a malware-feed verdict — state that caveat. Base every claim only on the ' +
        'evidence provided; never invent ports, CVEs, or findings.';
      return complete(system, `Indicator: ${value} (${kind})\n\n${evidenceText}`, 1024);
    }

    // ── Parsed log detections → attack-chain triage ──
    function triageLog(evidenceText) {
      const system =
        'You are a senior SOC analyst. You are given the detections SentinelX parsed from a batch of raw ' +
        'logs — each line matched to a pattern and, where applicable, a MITRE ATT&CK technique — plus the ' +
        'public source IPs seen. Write a concise triage in markdown with these sections: **What happened** ' +
        '(one paragraph narrating the likely activity and attack chain, in ATT&CK terms where the data ' +
        'supports it), **Notable actors** (bullets — which IPs matter and why), and **Recommended actions** ' +
        '(concrete, bulleted). Base every claim only on the detections provided; never invent events, IPs, or ' +
        'techniques. If the activity looks benign or inconclusive, say so.';
      return complete(system, evidenceText, 1536);
    }

    // ── Reusable modal (single overlay, content replaced on each call) ──
    const MODAL_STYLE =
      '.ai-md{color:var(--text-1);line-height:1.55;font-size:14px}' +
      '.ai-md h2,.ai-md h3,.ai-md h4{color:var(--text-1);margin:14px 0 6px}' +
      '.ai-md h2{font-size:16px}.ai-md h3{font-size:14px;color:var(--text-2)}.ai-md h4{font-size:13px;color:var(--text-2)}' +
      '.ai-md p{margin:8px 0}.ai-md ul{margin:6px 0 10px;padding-left:20px}.ai-md li{margin:3px 0}' +
      '.ai-md code{font-family:var(--f-mono);background:var(--bg-card);padding:1px 5px;border-radius:4px;font-size:12px}' +
      '.ai-md strong{color:var(--text-1)}';

    function modal(title, html) {
      if (!document.getElementById('ai-style')) {
        const st = document.createElement('style');
        st.id = 'ai-style';
        st.textContent = MODAL_STYLE;
        document.head.appendChild(st);
      }
      let ov = document.getElementById('ai-modal');
      if (!ov) {
        ov = document.createElement('div');
        ov.id = 'ai-modal';
        ov.setAttribute('style', 'position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:9999;padding:20px');
        ov.innerHTML =
          '<div style="background:var(--bg-panel);border:1px solid var(--border);border-radius:10px;max-width:720px;width:100%;max-height:85vh;display:flex;flex-direction:column">' +
            '<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 18px;border-bottom:1px solid var(--border)">' +
              '<span class="ai-modal-title" style="font-weight:600;color:var(--text-1)"></span>' +
              '<button class="ai-modal-close" aria-label="Close" style="background:none;border:none;color:var(--text-3);font-size:22px;cursor:pointer;line-height:1">×</button>' +
            '</div>' +
            '<div class="ai-modal-body" style="padding:16px 18px;overflow:auto"></div>' +
          '</div>';
        document.body.appendChild(ov);
        ov.querySelector('.ai-modal-close').addEventListener('click', () => ov.remove());
        ov.addEventListener('click', (e) => { if (e.target === ov) ov.remove(); });
      }
      ov.querySelector('.ai-modal-title').textContent = title;   // textContent → safe
      ov.querySelector('.ai-modal-body').innerHTML = html;
      return ov;
    }

    // ── Settings key UI (mirrors abuseipdb.js) ──
    function wireKeyUI() {
      const input = document.getElementById('ai-apikey');
      const saveBtn = document.getElementById('ai-save-key');
      const status = document.getElementById('ai-key-status');
      if (!input) return;
      const refresh = () => {
        if (status) status.innerHTML = hasKey()
          ? '<span style="color:var(--green)">✓ Key configured</span>'
          : '<span style="color:var(--text-3)">No key set</span>';
      };
      input.value = getKey();
      refresh();
      saveBtn?.addEventListener('click', () => {
        setKey(input.value.trim());
        refresh();
        (window.showToast || (() => {}))(hasKey() ? 'Claude API key saved' : 'Claude API key cleared', hasKey() ? 'success' : 'warn');
      });
    }

    window.AI = { hasKey, requireKey, summarizeCase, explainIntel, triageLog, mdToHtml, modal };

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wireKeyUI);
    else wireKeyUI();
  }

  // ── Node self-check (pure logic only): node js/ai.js ──
  if (!isBrowser && typeof require !== 'undefined' && require.main === module) {
    const assert = require('assert');
    assert.strictEqual(escapeHtml('<b>&"\''), '&lt;b&gt;&amp;&quot;&#39;');
    assert.ok(!mdToHtml('<script>alert(1)</script>').includes('<script>'), 'must escape tags');
    assert.ok(mdToHtml('**x**').includes('<strong>x</strong>'), 'bold');
    assert.ok(mdToHtml('- a\n- b').includes('<li>a</li>') && mdToHtml('- a\n- b').includes('<ul>'), 'list');
    assert.ok(mdToHtml('## Head').includes('<h3>Head</h3>'), 'heading downshift');
    assert.ok(mdToHtml('`c`').includes('<code>c</code>'), 'code');
    console.log('ai.js self-check ok');
  }
})();
