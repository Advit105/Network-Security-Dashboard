// ── Password Strength Checker ──────────────────────

const COMMON_PASSWORDS = [
  'password','123456','password123','admin','letmein','qwerty',
  'abc123','monkey','1234567','iloveyou','12345678','welcome',
  'login','password1','sunshine','princess','master','dragon',
  'shadow','superman','michael','football','baseball','soccer',
];

const RULES = [
  { id: 'rule-length',   label: 'At least 12 characters',          test: p => p.length >= 12 },
  { id: 'rule-upper',    label: 'Uppercase letter (A–Z)',           test: p => /[A-Z]/.test(p) },
  { id: 'rule-lower',    label: 'Lowercase letter (a–z)',           test: p => /[a-z]/.test(p) },
  { id: 'rule-number',   label: 'Number (0–9)',                     test: p => /[0-9]/.test(p) },
  { id: 'rule-special',  label: 'Special character (!@#$%^&*)',     test: p => /[^A-Za-z0-9]/.test(p) },
  { id: 'rule-nocommon', label: 'Not a common password',            test: p => !COMMON_PASSWORDS.includes(p.toLowerCase()) },
  { id: 'rule-norepeats',label: 'No repeated characters (aaa)',     test: p => !/(.)\1{2,}/.test(p) },
  { id: 'rule-length16', label: 'Bonus: 16+ characters',           test: p => p.length >= 16 },
];

function calcEntropy(password) {
  const charsets = [
    { regex: /[a-z]/, size: 26 },
    { regex: /[A-Z]/, size: 26 },
    { regex: /[0-9]/, size: 10 },
    { regex: /[^A-Za-z0-9]/, size: 32 },
  ];
  const poolSize = charsets.reduce((acc, c) => acc + (c.regex.test(password) ? c.size : 0), 0);
  return poolSize > 0 ? (password.length * Math.log2(poolSize)).toFixed(1) : 0;
}

function getStrengthLevel(score, total) {
  const pct = score / total;
  if (pct <= 0.3) return { label: 'Very Weak', cls: 'danger',  width: '15%' };
  if (pct <= 0.5) return { label: 'Weak',      cls: 'danger',  width: '30%' };
  if (pct <= 0.65)return { label: 'Fair',       cls: 'warn',    width: '50%' };
  if (pct <= 0.8) return { label: 'Strong',     cls: 'success', width: '75%' };
  return              { label: 'Very Strong',   cls: 'success', width: '100%' };
}

function analyzePassword(password) {
  if (!password) return;

  const results = RULES.map(rule => ({ ...rule, passed: rule.test(password) }));
  const score   = results.filter(r => r.passed).length;
  const entropy = calcEntropy(password);
  const level   = getStrengthLevel(score, RULES.length);

  // Update strength bar
  const bar   = document.getElementById('strength-bar');
  const label = document.getElementById('strength-label');
  bar.style.width      = level.width;
  bar.className        = `strength-fill ${level.cls}`;
  label.textContent    = level.label;
  label.className      = `strength-label-text ${level.cls}`;

  // Update entropy
  document.getElementById('entropy-val').textContent = `${entropy} bits`;

  // Update crack time estimate
  const crackTime = estimateCrackTime(entropy);
  document.getElementById('crack-time').textContent = crackTime;

  // Update rules checklist
  const list = document.getElementById('rules-list');
  list.innerHTML = results.map(r => `
    <div class="rule-row ${r.passed ? 'passed' : 'failed'}">
      <span class="rule-icon">${r.passed ? '✓' : '✕'}</span>
      <span class="rule-label">${r.label}</span>
    </div>
  `).join('');
}

function estimateCrackTime(entropy) {
  // Assumes 10 billion guesses/sec (modern GPU cluster)
  const guesses = Math.pow(2, parseFloat(entropy));
  const seconds = guesses / 1e10;

  if (seconds < 1)         return 'Instantly';
  if (seconds < 60)        return `${Math.round(seconds)} seconds`;
  if (seconds < 3600)      return `${Math.round(seconds/60)} minutes`;
  if (seconds < 86400)     return `${Math.round(seconds/3600)} hours`;
  if (seconds < 2592000)   return `${Math.round(seconds/86400)} days`;
  if (seconds < 31536000)  return `${Math.round(seconds/2592000)} months`;
  if (seconds < 3153600000)return `${Math.round(seconds/31536000)} years`;
  return 'Centuries';
}

// ── Generate Strong Password ───────────────────────
function generatePassword(length = 20) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}';
  const arr   = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => chars[b % chars.length]).join('');
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
    analyzePassword(input.value);
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
    analyzePassword(pw);
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
