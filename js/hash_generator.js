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
      <button class="copy-hash-btn" onclick="copyHash('hash-sha256', this)">Copy</button>
    </div>
    <div class="hash-row">
      <div class="hash-algo">SHA-1</div>
      <div class="hash-val" id="hash-sha1">${hashes.sha1}</div>
      <button class="copy-hash-btn" onclick="copyHash('hash-sha1', this)">Copy</button>
    </div>
    <div class="hash-row">
      <div class="hash-algo">SHA-512</div>
      <div class="hash-val" id="hash-sha512">${hashes.sha512}</div>
      <button class="copy-hash-btn" onclick="copyHash('hash-sha512', this)">Copy</button>
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
    : `<span>✕ Hash does not match — input may be tampered</span><span class="result-raw">Expected: ${expected}<br>Got: ${actual}</span>`;

  showToast(match ? 'Hash verified — match!' : 'Hash mismatch detected', match ? 'success' : 'danger');
}

// ── Event Listeners ────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const btn   = document.getElementById('hash-btn');
  const input = document.getElementById('hash-input');
  if (!btn || !input) return;

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

  document.getElementById('clear-hash-btn').addEventListener('click', () => {
    input.value = '';
    document.getElementById('hash-results').style.display = 'none';
    document.getElementById('verify-input').value = '';
    document.getElementById('verify-hash').value  = '';
    document.getElementById('verify-result').style.display = 'none';
  });
});
