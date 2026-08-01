// ═══════════════════════════════════════════════════
//  decoder.js — CyberChef-lite data decoder
//  Base64 / Hex / URL / HTML / ROT13 / JWT / gzip /
//  timestamps / defang-refang, plus a "Magic" mode that
//  auto-detects and peels encoding layers.
//  100% client-side — nothing ever leaves the browser.
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  const enc = new TextEncoder();
  const dec = new TextDecoder('utf-8', { fatal: false });

  // ── byte helpers ──────────────────────────────────
  function bytesToB64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
  }
  function b64ToBytes(s) {
    // tolerate URL-safe alphabet, whitespace and missing padding
    let t = s.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    if (t.length % 4) t += '='.repeat(4 - (t.length % 4));
    const bin = atob(t);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  const looksB64 = (s) => {
    const t = s.trim().replace(/\s+/g, '');
    return t.length >= 8 && t.length % 4 !== 1 && /^[A-Za-z0-9+/\-_]+={0,2}$/.test(t);
  };
  const looksHex = (s) => {
    const t = s.trim().replace(/^0x/i, '').replace(/[\s:,]+/g, '');
    return t.length >= 6 && t.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(t);
  };
  // Rough printability check — is a decode result human-readable text?
  const printable = (s) => {
    if (!s.length) return false;
    let ok = 0;
    for (const ch of s) {
      const c = ch.codePointAt(0);
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 0xfffd && c !== 0xfffd)) ok++;
    }
    return ok / [...s].length > 0.9 && !s.includes('�');
  };

  function fmtEpoch(n) {
    const d = new Date(n);
    if (isNaN(d)) return null;
    const rel = Math.round((d - Date.now()) / 1000);
    const abs = Math.abs(rel);
    const unit = abs >= 86400 ? [Math.round(abs / 86400), 'd'] : abs >= 3600 ? [Math.round(abs / 3600), 'h'] : [Math.round(abs / 60), 'm'];
    return `${d.toISOString()}  (local: ${d.toLocaleString()}, ${unit[0]}${unit[1]} ${rel < 0 ? 'ago' : 'from now'})`;
  }

  // ── operations ────────────────────────────────────
  // Each op: id, label, group, run(text) → string (may throw with a friendly message)
  const OPS = [
    { id: 'magic', label: '✨ Magic', group: 'auto', run: magic },

    { id: 'b64d', label: 'From Base64', group: 'decode', run: (t) => {
        if (!looksB64(t)) throw 'Input doesn\'t look like Base64.';
        const out = dec.decode(b64ToBytes(t));
        if (!printable(out)) throw 'Decodes to binary, not text — if it\'s gzipped, try "Gunzip (b64)".';
        return out;
      } },
    { id: 'hexd', label: 'From Hex', group: 'decode', run: (t) => {
        if (!looksHex(t)) throw 'Input doesn\'t look like hex (need an even number of 0-9 a-f chars).';
        const clean = t.trim().replace(/^0x/i, '').replace(/[\s:,]+/g, '');
        const bytes = new Uint8Array(clean.length / 2);
        for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
        return dec.decode(bytes);
      } },
    { id: 'urld', label: 'URL Decode', group: 'decode', run: (t) => {
        try { return decodeURIComponent(t.replace(/\+/g, '%20')); }
        catch { throw 'Malformed percent-encoding.'; }
      } },
    { id: 'htmld', label: 'HTML Entities →', group: 'decode', run: (t) => {
        const el = document.createElement('textarea');
        el.innerHTML = t.replace(/</g, '&lt;'); // neutralize tags, keep entities
        return el.value;
      } },
    { id: 'jwt', label: 'JWT Decode', group: 'decode', run: (t) => {
        const parts = t.trim().split('.');
        if (parts.length !== 3) throw 'Not a JWT (expected three dot-separated Base64URL parts).';
        const [h, p] = parts.slice(0, 2).map((x) => JSON.parse(dec.decode(b64ToBytes(x))));
        let out = '── HEADER ──\n' + JSON.stringify(h, null, 2) + '\n\n── PAYLOAD ──\n' + JSON.stringify(p, null, 2);
        const notes = [];
        if (String(h.alg).toLowerCase() === 'none') notes.push('⚠ alg=none — unsigned token, forgeable');
        for (const k of ['exp', 'iat', 'nbf']) {
          if (typeof p[k] === 'number') notes.push(`${k}: ${fmtEpoch(p[k] * 1000)}`);
        }
        if (typeof p.exp === 'number' && p.exp * 1000 < Date.now()) notes.push('⚠ token is EXPIRED');
        notes.push('Signature not verified — decoding ≠ trusting.');
        return out + '\n\n── NOTES ──\n' + notes.join('\n');
      } },
    { id: 'gunzip', label: 'Gunzip (b64)', group: 'decode', run: async (t) => {
        if (typeof DecompressionStream === 'undefined') throw 'This browser lacks DecompressionStream.';
        if (!looksB64(t)) throw 'Expected Base64-wrapped gzip data (starts with H4sI…).';
        const bytes = b64ToBytes(t);
        const format = bytes[0] === 0x1f && bytes[1] === 0x8b ? 'gzip' : 'deflate';
        const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
        try { return await new Response(stream).text(); }
        catch { throw 'Not valid gzip/deflate data.'; }
      } },
    { id: 'ts', label: 'Timestamp', group: 'decode', run: (t) => {
        const n = Number(t.trim());
        if (!isFinite(n) || t.trim() === '') throw 'Enter a numeric Unix timestamp.';
        const lines = [];
        const secs = fmtEpoch(n * 1000), ms = fmtEpoch(n);
        if (n > 1e11) { if (ms) lines.push('as milliseconds:  ' + ms); }
        else if (secs) lines.push('as seconds:       ' + secs);
        if (!lines.length) throw 'Out of range for a plausible date.';
        return lines.join('\n');
      } },
    { id: 'refang', label: 'Refang', group: 'decode', run: (t) => t
        .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
        .replace(/\[:\]|\[colon\]/gi, ':')
        .replace(/\[at\]|\(at\)/gi, '@')
        .replace(/\[\/\]/g, '/')
        .replace(/h(?:xx|XX|\[x\])p(s?)/gi, 'http$1') },
    { id: 'rot13', label: 'ROT13', group: 'decode', run: (t) =>
        t.replace(/[a-zA-Z]/g, (c) => {
          const base = c <= 'Z' ? 65 : 97;
          return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
        }) },

    { id: 'b64e', label: 'To Base64', group: 'encode', run: (t) => bytesToB64(enc.encode(t)) },
    { id: 'hexe', label: 'To Hex', group: 'encode', run: (t) =>
        [...enc.encode(t)].map((b) => b.toString(16).padStart(2, '0')).join('') },
    { id: 'urle', label: 'URL Encode', group: 'encode', run: (t) => encodeURIComponent(t) },
    { id: 'htmle', label: '→ HTML Entities', group: 'encode', run: (t) =>
        t.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])) },
    { id: 'defang', label: 'Defang', group: 'encode', run: (t) => t
        .replace(/http(s?):\/\//gi, 'hxxp$1://')
        .replace(/(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})/g, '$1[.]$2')
        .replace(/([a-z0-9-]+)\.([a-z]{2,})(?=[\s/:"']|$)/gim, '$1[.]$2') },
  ];
  const opById = Object.fromEntries(OPS.map((o) => [o.id, o]));

  // ── Magic: peel encoding layers until nothing matches ──
  async function magic(input) {
    const steps = [];
    let cur = input.trim();
    for (let i = 0; i < 6; i++) {
      // JWT is terminal — decode and stop
      if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(cur)) {
        steps.push('JWT decode');
        cur = await opById.jwt.run(cur);
        break;
      }
      if (looksB64(cur)) {
        const bytes = b64ToBytes(cur);
        if (bytes[0] === 0x1f && bytes[1] === 0x8b) {           // gzip magic
          steps.push('Base64 → gunzip');
          cur = await opById.gunzip.run(cur);
          continue;
        }
        const txt = dec.decode(bytes);
        if (printable(txt) && txt !== cur) { steps.push('Base64 decode'); cur = txt; continue; }
      }
      if (looksHex(cur)) {
        const txt = opById.hexd.run(cur);
        if (printable(txt)) { steps.push('Hex decode'); cur = txt; continue; }
      }
      if (/%[0-9a-fA-F]{2}/.test(cur)) {
        try {
          const txt = decodeURIComponent(cur);
          if (txt !== cur) { steps.push('URL decode'); cur = txt; continue; }
        } catch { /* not URL-encoded after all */ }
      }
      if (/^\d{9,13}$/.test(cur)) { steps.push('Unix timestamp'); cur = opById.ts.run(cur); break; }
      if (/hxxp|\[\.\]|\[at\]/i.test(cur)) { steps.push('Refang'); cur = opById.refang.run(cur); continue; }
      break;
    }
    if (!steps.length) throw 'No known encoding detected — try a specific operation.';
    return `── DETECTED: ${steps.join(' → ')} ──\n\n${cur}`;
  }

  // ── UI wiring ─────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    const input   = document.getElementById('dec-input');
    const output  = document.getElementById('dec-output');
    const opsWrap = document.getElementById('dec-ops');
    const status  = document.getElementById('dec-status');
    const copyBtn = document.getElementById('dec-copy-btn');
    const chainBtn = document.getElementById('dec-chain-btn');
    if (!input || !opsWrap) return;

    let activeOp = null;

    // Build the operation chip rows
    const groups = [['auto', 'AUTO'], ['decode', 'DECODE'], ['encode', 'ENCODE']];
    opsWrap.innerHTML = groups.map(([g, label]) => `
      <div class="dec-op-row">
        <span class="dec-op-group">${label}</span>
        ${OPS.filter((o) => o.group === g).map((o) => `<button class="dec-op" data-op="${o.id}">${o.label}</button>`).join('')}
      </div>`).join('');

    async function run(opId) {
      const op = opById[opId];
      if (!op) return;
      activeOp = opId;
      opsWrap.querySelectorAll('.dec-op').forEach((b) => b.classList.toggle('active', b.dataset.op === opId));
      const text = input.value;
      if (!text.trim()) {
        output.textContent = '';
        status.textContent = 'Waiting for input…';
        status.className = 'alert-badge info';
        return;
      }
      try {
        const result = await op.run(text);
        output.textContent = result;
        status.textContent = `${op.label} · ${result.length} chars`;
        status.className = 'alert-badge success';
        copyBtn.style.display = chainBtn.style.display = '';
      } catch (e) {
        output.textContent = '';
        status.textContent = typeof e === 'string' ? e : (e.message || 'Failed');
        status.className = 'alert-badge danger';
        copyBtn.style.display = chainBtn.style.display = 'none';
      }
    }

    opsWrap.addEventListener('click', (e) => {
      const btn = e.target.closest('.dec-op');
      if (btn) run(btn.dataset.op);
    });

    // Re-run the active op live as the input changes (debounced)
    let debounce;
    input.addEventListener('input', () => {
      if (!activeOp) return;
      clearTimeout(debounce);
      debounce = setTimeout(() => run(activeOp), 250);
    });

    copyBtn?.addEventListener('click', () => {
      navigator.clipboard?.writeText(output.textContent).then(() => window.showToast?.('Output copied', 'success'));
    });
    chainBtn?.addEventListener('click', () => {
      input.value = output.textContent;
      output.textContent = '';
      status.textContent = 'Output moved to input — pick the next operation.';
      status.className = 'alert-badge info';
      input.focus();
    });
    document.getElementById('dec-clear-btn')?.addEventListener('click', () => {
      input.value = '';
      output.textContent = '';
      status.textContent = 'Waiting for input…';
      status.className = 'alert-badge info';
      copyBtn.style.display = chainBtn.style.display = 'none';
    });
    document.getElementById('dec-sample-btn')?.addEventListener('click', () => {
      input.value = 'aHR0cHM6Ly9sb2dpbi5taWNyMHNvZnQtc2VjdXJlLmNvbS9yZXNldD90b2tlbj1hYmMxMjM=';
      run('magic');
    });
  });
})();
