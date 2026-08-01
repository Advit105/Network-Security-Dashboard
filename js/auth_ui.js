// ═══════════════════════════════════════════════════
//  auth_ui.js — login/register modal, account widget,
//  and guest↔server blocklist sync coordination.
//
//  Sync model:
//    * DISPLAY_KEY (sentinelx_blocklist) is always what the app renders.
//    * On login we snapshot the current guest list into GUEST_KEY, then mirror
//      the server list into DISPLAY_KEY (server is source of truth while signed in).
//    * On logout we restore the guest snapshot. Nothing is lost either way.
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  const GUEST_KEY = 'sentinelx_blocklist_guest';
  const DISPLAY_KEY = 'sentinelx_blocklist';

  const $ = (id) => document.getElementById(id);
  let mode = 'login';       // 'login' | 'register'
  let pendingMfaToken = null;

  // ── Guest snapshot helpers ────────────────────────
  const backupGuest = () => localStorage.setItem(GUEST_KEY, localStorage.getItem(DISPLAY_KEY) || '[]');
  function restoreGuest() {
    localStorage.setItem(DISPLAY_KEY, localStorage.getItem(GUEST_KEY) || '[]');
    localStorage.removeItem(GUEST_KEY);
    if (typeof refreshBlocklistViews === 'function') refreshBlocklistViews();
  }

  async function hydrateFromServer() {
    try {
      const list = await SentinelAPI.listBlocklist();
      if (typeof setBlocklistFromServer === 'function') setBlocklistFromServer(list);
    } catch {
      // offline — keep whatever is displayed
    }
  }

  // ── Account widget ────────────────────────────────
  function renderWidget(state) {
    const signin = $('account-signin');
    const info = $('account-info');
    if (!signin || !info) return;
    if (state.user) {
      signin.style.display = 'none';
      info.style.display = 'flex';
      // Rail layout hides the email text — surface it via the hover tooltip.
      info.setAttribute('data-tip', state.user.email);
      $('account-avatar').textContent = (state.user.email[0] || '?').toUpperCase();
      $('account-email').textContent = state.user.email;
      const st = $('account-status');
      st.textContent = state.online === false ? 'Offline' : 'Synced';
      st.className = 'account-status' + (state.online === false ? ' offline' : '');
    } else {
      // A Google session (gauth.js) owns the widget — don't reset it to signed-out.
      if (window.GAuth && GAuth.isSignedIn()) return;
      signin.style.display = 'flex';
      info.style.display = 'none';
    }
  }

  // ── Modal open/close + mode ───────────────────────
  function openModal() {
    setMode('login');
    $('auth-modal').classList.add('modal-open');
    setTimeout(() => $('auth-email').focus(), 40);
  }
  function closeModal() {
    $('auth-modal').classList.remove('modal-open');
    resetForm();
  }
  function resetForm() {
    $('auth-form-step').style.display = 'block';
    $('auth-mfa-step').style.display = 'none';
    $('auth-error').style.display = 'none';
    $('auth-mfa-error').style.display = 'none';
    $('auth-password').value = '';
    $('auth-mfa-code').value = '';
    pendingMfaToken = null;
  }
  function setMode(m) {
    mode = m;
    const reg = m === 'register';
    $('auth-title').textContent = reg ? 'Create your account' : 'Sign in to SentinelX';
    $('auth-submit').textContent = reg ? 'Create Account' : 'Sign In';
    $('auth-toggle-text').textContent = reg ? 'Already have an account?' : 'No account?';
    $('auth-toggle-link').textContent = reg ? 'Sign in' : 'Create one';
    $('auth-pw-hint').style.display = reg ? 'block' : 'none';
    $('auth-password').setAttribute('autocomplete', reg ? 'new-password' : 'current-password');
    $('auth-error').style.display = 'none';
  }
  const showErr = (el, msg) => { el.textContent = msg; el.style.display = 'block'; };

  // ── Submit (login or register) ────────────────────
  async function submit() {
    const email = $('auth-email').value.trim();
    const password = $('auth-password').value;
    const btn = $('auth-submit');
    const errEl = $('auth-error');
    errEl.style.display = 'none';
    if (!email || !password) { showErr(errEl, 'Enter your email and password.'); return; }

    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = mode === 'register' ? 'Creating…' : 'Signing in…';
    try {
      if (mode === 'register') {
        await SentinelAPI.register(email, password);
      }
      const r = await SentinelAPI.login(email, password);
      if (r.mfa_required) {
        pendingMfaToken = r.mfa_token;
        $('auth-form-step').style.display = 'none';
        $('auth-mfa-step').style.display = 'block';
        setTimeout(() => $('auth-mfa-code').focus(), 40);
        return;
      }
      await onAuthenticated(false);
      closeModal();
      showToast?.(`Signed in as ${r.user.email}`, 'success');
    } catch (err) {
      showErr(errEl, friendlyError(err, mode));
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  }

  async function submitMfa() {
    const code = $('auth-mfa-code').value.trim();
    const errEl = $('auth-mfa-error');
    errEl.style.display = 'none';
    if (code.length !== 6) { showErr(errEl, 'Enter the 6-digit code.'); return; }
    const btn = $('auth-mfa-submit');
    btn.disabled = true; btn.textContent = 'Verifying…';
    try {
      const user = await SentinelAPI.verifyMfa(pendingMfaToken, code);
      await onAuthenticated(false);
      closeModal();
      showToast?.(`Signed in as ${user.email}`, 'success');
    } catch (err) {
      showErr(errEl, err.status === 401 ? 'Invalid or expired code.' : friendlyError(err, 'login'));
    } finally {
      btn.disabled = false; btn.textContent = 'Verify';
    }
  }

  function friendlyError(err, m) {
    if (!err || err.status === 0) return 'Cannot reach the server. Is the backend running?';
    if (err.status === 401) return 'Invalid email or password.';
    if (err.status === 409) return m === 'register' ? 'That email is already registered.' : 'Conflict.';
    if (err.status === 429) return 'Too many attempts or account locked. Try again later.';
    if (err.status === 422) return m === 'register'
      ? 'Password needs 12+ chars with upper, lower, number & symbol.'
      : 'Invalid input.';
    return err.message || 'Something went wrong.';
  }

  // ── Auth state transitions ────────────────────────
  async function onAuthenticated(fromBootstrap) {
    if (!fromBootstrap) backupGuest();   // snapshot guest list on an explicit login
    await hydrateFromServer();
  }
  async function doLogout() {
    // Google session? Let gauth.js handle sign-out + guest restore.
    if (window.GAuth && GAuth.isSignedIn()) { await GAuth.signOut(); return; }
    await SentinelAPI.logout();
    restoreGuest();
    showToast?.('Signed out — back to local mode', 'info');
  }

  // ── Wire up ───────────────────────────────────────
  document.addEventListener('DOMContentLoaded', async () => {
    if (!window.SentinelAPI) return;

    SentinelAPI.onChange(renderWidget);

    $('account-signin')?.addEventListener('click', openModal);
    $('account-signout')?.addEventListener('click', doLogout);
    $('auth-close')?.addEventListener('click', closeModal);
    $('auth-modal')?.addEventListener('click', (e) => { if (e.target.id === 'auth-modal') closeModal(); });
    $('auth-toggle-link')?.addEventListener('click', (e) => { e.preventDefault(); setMode(mode === 'login' ? 'register' : 'login'); });
    $('auth-submit')?.addEventListener('click', submit);
    $('auth-mfa-submit')?.addEventListener('click', submitMfa);
    $('auth-password')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
    $('auth-email')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') $('auth-password').focus(); });
    $('auth-mfa-code')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') submitMfa(); });

    // Bootstrap session on load.
    const user = await SentinelAPI.bootstrap();
    if (user) {
      await onAuthenticated(true);
    } else if (localStorage.getItem(GUEST_KEY) !== null) {
      restoreGuest();   // leftover snapshot from a prior signed-in session
    }
    renderWidget(SentinelAPI.state);
  });
})();
