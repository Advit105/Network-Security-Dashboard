// ── Credential Exposure (k-anonymous breach check) ──
// The consumer strength meter was removed 2026-08: analysts check whether a
// credential is EXPOSED, not how it scores on complexity rules. Breach check
// (HIBP range API) + throwaway generation are the SOC-relevant parts.

// ── Generate Strong Password ───────────────────────
function generatePassword(length = 20) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}';
  // Rejection sampling: bytes ≥ the largest multiple of chars.length are
  // discarded, so no character is more likely than another (b % 80 biases).
  const limit = 256 - (256 % chars.length);
  let out = '';
  while (out.length < length) {
    const arr = new Uint8Array(length * 2);
    crypto.getRandomValues(arr);
    for (const b of arr) {
      if (b < limit && out.length < length) out += chars[b % chars.length];
    }
  }
  return out;
}

// ── Have I Been Pwned Breach Check ─────────────────
async function checkBreach(password) {
  const breachEl = document.getElementById('breach-result');
  if (!breachEl) return;

  if (!password) {
    breachEl.style.display = 'none';
    return;
  }

  breachEl.style.display = 'flex';
  breachEl.className = 'breach-result loading';
  breachEl.innerHTML = '<span class="breach-icon">⏳</span><span>Checking breach databases...</span>';

  try {
    // SHA-1 hash the password
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    const prefix = hashHex.slice(0, 5);
    const suffix = hashHex.slice(5);

    // Query HIBP API with k-anonymity (only sends first 5 chars)
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    const text = await res.text();

    // Check if our suffix appears in the results
    const lines = text.split('\n');
    let count = 0;
    for (const line of lines) {
      const [hashSuffix, c] = line.split(':');
      if (hashSuffix.trim() === suffix) {
        count = parseInt(c.trim(), 10);
        break;
      }
    }

    if (count > 0) {
      breachEl.className = 'breach-result danger';
      breachEl.innerHTML = `<span class="breach-icon">⚠</span><div><strong>Breached!</strong> This password appeared in <strong>${count.toLocaleString()}</strong> known data breaches. Do not use it.</div>`;
    } else {
      breachEl.className = 'breach-result safe';
      breachEl.innerHTML = `<span class="breach-icon">✓</span><div><strong>Safe</strong> — This password has not been found in any known data breaches.</div>`;
    }
  } catch (err) {
    breachEl.className = 'breach-result warn';
    breachEl.innerHTML = `<span class="breach-icon">!</span><div>Could not check breaches. You may be offline or the API is unavailable.</div>`;
  }
}

// ── Event Listeners ────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const input   = document.getElementById('pw-input');
  const showBtn = document.getElementById('pw-show-btn');
  const genBtn  = document.getElementById('pw-gen-btn');
  const copyBtn = document.getElementById('pw-copy-btn');

  if (!input) return;

  let breachTimeout;
  input.addEventListener('input', () => {
    // Debounce breach check to avoid spamming API
    clearTimeout(breachTimeout);
    breachTimeout = setTimeout(() => checkBreach(input.value), 600);
  });

  showBtn.addEventListener('click', () => {
    const isHidden = input.type === 'password';
    input.type     = isHidden ? 'text' : 'password';
    showBtn.textContent = isHidden ? 'Hide' : 'Show';
  });

  genBtn.addEventListener('click', () => {
    const pw       = generatePassword(20);
    input.type     = 'text';
    input.value    = pw;
    showBtn.textContent = 'Hide';
    checkBreach(pw);
    showToast('Strong password generated', 'success');
  });

  copyBtn.addEventListener('click', () => {
    if (!input.value) { showToast('Nothing to copy', 'warn'); return; }
    navigator.clipboard.writeText(input.value).then(() => {
      showToast('Password copied to clipboard', 'success');
    });
  });
});
