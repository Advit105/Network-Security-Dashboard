// ── Hash Generator using Web Crypto API ───────────

async function hashText(text, algorithm) {
  const encoder = new TextEncoder();
  const data    = encoder.encode(text);
  const hashBuf = await crypto.subtle.digest(algorithm, data);
  const hashArr = Array.from(new Uint8Array(hashBuf));
  return hashArr.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function generateHashes(input) {
  if (!input) return null;

  const [sha256, sha1, sha512] = await Promise.all([
    hashText(input, 'SHA-256'),
    hashText(input, 'SHA-1'),
    hashText(input, 'SHA-512'),
  ]);

  return { sha256, sha1, sha512 };
}

function renderHashResults(hashes) {
  const results = document.getElementById('hash-results');
  if (!results) return;

  results.style.display = 'flex';
  results.innerHTML = `
    <div class="hash-row">
      <div class="hash-algo">SHA-256</div>
      <div class="hash-val" id="hash-sha256">${hashes.sha256}</div>
      <button class="copy-hash-btn" data-copy-hash="hash-sha256">Copy</button>
    </div>
    <div class="hash-row">
      <div class="hash-algo">SHA-1</div>
      <div class="hash-val" id="hash-sha1">${hashes.sha1}</div>
      <button class="copy-hash-btn" data-copy-hash="hash-sha1">Copy</button>
    </div>
    <div class="hash-row">
      <div class="hash-algo">SHA-512</div>
      <div class="hash-val" id="hash-sha512">${hashes.sha512}</div>
      <button class="copy-hash-btn" data-copy-hash="hash-sha512">Copy</button>
    </div>
  `;
}

function copyHash(id, btn) {
  const val = document.getElementById(id).textContent;
  navigator.clipboard.writeText(val).then(() => {
    btn.textContent = 'Copied!';
    showToast('Hash copied to clipboard', 'success');
    setTimeout(() => btn.textContent = 'Copy', 1500);
  });
}

// ── Verify Hash ────────────────────────────────────
async function verifyHash() {
  const input    = document.getElementById('verify-input').value.trim();
  const expected = document.getElementById('verify-hash').value.trim().toLowerCase();
  const algo     = document.getElementById('verify-algo').value;
  const resultEl = document.getElementById('verify-result');

  if (!input || !expected) {
    showToast('Enter both text and hash to verify', 'warn');
    return;
  }

  const algoMap = { sha256: 'SHA-256', sha1: 'SHA-1', sha512: 'SHA-512' };
  const actual  = await hashText(input, algoMap[algo]);

  const match = actual === expected;
  resultEl.style.display = 'flex';
  resultEl.className     = `verify-result ${match ? 'success' : 'danger'}`;
  resultEl.innerHTML     = match
    ? `<span>✓ Hash matches — input is authentic</span>`
    : `<span>✕ Hash does not match — input may be tampered</span><span class="result-raw">Expected: ${escHtml(expected)}<br>Got: ${actual}</span>`;

  showToast(match ? 'Hash verified — match!' : 'Hash mismatch detected', match ? 'success' : 'danger');
}

// ── Event Listeners ────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const btn   = document.getElementById('hash-btn');
  const input = document.getElementById('hash-input');
  if (!btn || !input) return;

  // Web Crypto needs a secure context (https / localhost) — fail with a
  // message instead of a silent TypeError when served over plain http.
  if (!crypto.subtle) {
    btn.addEventListener('click', () =>
      showToast('Web Crypto unavailable — open the app via localhost or HTTPS', 'danger'));
    return;
  }

  btn.addEventListener('click', async () => {
    const text = input.value.trim();
    if (!text) { showToast('Enter some text to hash', 'warn'); return; }
    const hashes = await generateHashes(text);
    renderHashResults(hashes);
    showToast('Hashes generated', 'success');
  });

  // Live hash as user types (debounced)
  let timer;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const text = input.value.trim();
      if (!text) { document.getElementById('hash-results').style.display = 'none'; return; }
      const hashes = await generateHashes(text);
      renderHashResults(hashes);
    }, 400);
  });

  document.getElementById('verify-btn').addEventListener('click', verifyHash);

  // ── File Hash Intel: hash a local file (never uploaded) / look up a pasted hash ──
  const lookupEl = document.getElementById('hashlookup-result');
  function renderHashIntel(hash, fileName) {
    const kind = /^[0-9a-f]+$/i.test(hash) ? { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256' }[hash.length] : null;
    if (!kind) {
      lookupEl.style.display = 'block';
      lookupEl.innerHTML = `<div class="intel-noev" style="padding:10px 0">Not a recognizable hash (need 32, 40, or 64 hex chars).</div>`;
      return;
    }
    const h = encodeURIComponent(hash);
    lookupEl.style.display = 'block';
    // Reputation APIs (VT / MalwareBazaar / CIRCL) require keys and block browser
    // CORS — deep-linking the hash into their web UIs is the honest client-side play.
    lookupEl.innerHTML = `
      ${fileName ? `<div class="intel-kv" style="margin-top:10px"><b>File</b><span>${escHtml(fileName)}</span></div>` : ''}
      <div class="intel-kv"><b>${kind}</b><span class="mono">${escHtml(hash)}</span></div>
      <div class="intel-pivots">
        <a class="ioc-pivot" href="https://www.virustotal.com/gui/file/${h}" target="_blank" rel="noopener">VirusTotal ↗</a>
        <a class="ioc-pivot" href="https://bazaar.abuse.ch/browse.php?search=hash%3A${h}" target="_blank" rel="noopener">MalwareBazaar ↗</a>
        <button class="ioc-copy" data-copy="${escHtml(hash)}">Copy</button>
      </div>`;
  }

  document.getElementById('hashfile-input')?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 256 * 1024 * 1024) { showToast('File too large (256 MB max)', 'warn'); return; }
    const buf = await file.arrayBuffer();
    const arr = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', buf)));
    const hash = arr.map(b => b.toString(16).padStart(2, '0')).join('');
    document.getElementById('hashlookup-input').value = hash;
    renderHashIntel(hash, `${file.name} (${(file.size / 1024).toFixed(1)} KB, hashed locally)`);
  });

  let lookupTimer;
  document.getElementById('hashlookup-input')?.addEventListener('input', (e) => {
    clearTimeout(lookupTimer);
    const v = e.target.value.trim().toLowerCase();
    if (!v) { lookupEl.style.display = 'none'; return; }
    lookupTimer = setTimeout(() => renderHashIntel(v), 350);
  });

  document.getElementById('clear-hash-btn').addEventListener('click', () => {
    input.value = '';
    document.getElementById('hash-results').style.display = 'none';
    document.getElementById('verify-input').value = '';
    document.getElementById('verify-hash').value  = '';
    document.getElementById('verify-result').style.display = 'none';
  });
});
