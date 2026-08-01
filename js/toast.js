// ── Toast Notification System ──────────────────────
// Usage: showToast('Message', 'success' | 'danger' | 'warn' | 'info')

// Shared HTML-escaper for every module that renders external or user data
// via innerHTML (DNS answers, CVE descriptions, cert fields, blocklist
// reasons…). toast.js loads first, so window.escHtml is always available.
window.escHtml = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function showToast(message, type = 'info', duration = 3000) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  const icons = { success: '✓', danger: '✕', warn: '⚠', info: 'ℹ' };

  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || icons.info}</span>
    <span class="toast-msg">${escHtml(message)}</span>
    <button class="toast-close" aria-label="Dismiss">×</button>
  `;
  // Listener (not inline onclick) so a strict CSP without 'unsafe-inline' works.
  toast.querySelector('.toast-close').addEventListener('click', () => toast.remove());

  container.appendChild(toast);

  // Animate in
  requestAnimationFrame(() => toast.classList.add('toast-visible'));

  // Auto remove
  setTimeout(() => {
    toast.classList.remove('toast-visible');
    setTimeout(() => toast.remove(), 300);
  }, duration);
}
