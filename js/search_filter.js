// ── Alert List Filter ──────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const alertSearch = document.getElementById('alert-search');
  if (!alertSearch) return;

  alertSearch.addEventListener('input', () => {
    const q    = alertSearch.value.trim().toLowerCase();
    const rows = document.querySelectorAll('#alert-list .alert-row');

    rows.forEach(row => {
      const text = row.dataset.text || row.textContent.toLowerCase();
      row.classList.toggle('hidden', q.length > 0 && !text.includes(q));
    });
  });
});

// ── Blocklist Table Filter ─────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const blSearch = document.getElementById('blocklist-search');
  if (!blSearch) return;

  blSearch.addEventListener('input', () => {
    const q    = blSearch.value.trim().toLowerCase();
    const rows = document.querySelectorAll('#blocklist-tbody tr');

    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      row.style.display = q.length > 0 && !text.includes(q) ? 'none' : '';
    });
  });
});
