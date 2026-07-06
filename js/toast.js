// ── Toast Notification System ──────────────────────
// Usage: showToast('Message', 'success' | 'danger' | 'warn' | 'info')

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
    <span class="toast-msg">${message}</span>
    <button class="toast-close" onclick="this.parentElement.remove()">×</button>
  `;

  container.appendChild(toast);

  // Animate in
  requestAnimationFrame(() => toast.classList.add('toast-visible'));

  // Auto remove
  setTimeout(() => {
    toast.classList.remove('toast-visible');
    setTimeout(() => toast.remove(), 300);
  }, duration);
}
