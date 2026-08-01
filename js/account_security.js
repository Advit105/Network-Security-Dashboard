// ═══════════════════════════════════════════════════
//  account_security.js — Settings › Account & Security
//  * Two-factor auth: enroll (QR + TOTP confirm) and disable.
//  * Signed-in devices: list refresh-token families, revoke any.
//  All data comes from the backend; nothing is fabricated client-side.
// ═══════════════════════════════════════════════════

(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  let mfaMode = 'enable';       // 'enable' | 'disable'
  let qrLibLoading = null;
  let sessionsFor = null;       // user id the device list was last fetched for

  // ── Panel state ───────────────────────────────────
  function renderPanel(state) {
    const out = $('acct-signedout');
    const inn = $('acct-signedin');
    if (!out || !inn) return;
    if (state.user) {
      out.style.display = 'none';
      inn.style.display = 'block';
      $('acct-email').textContent = state.user.email;
      const btn = $('acct-mfa-btn');
      const desc = $('acct-mfa-desc');
      if (state.user.mfa_enabled) {
        btn.textContent = 'Disable 2FA';
        btn.classList.add('danger-btn');
        desc.textContent = 'Enabled — every sign-in requires an authenticator code.';
      } else {
        btn.textContent = 'Enable 2FA';
        btn.classList.remove('danger-btn');
        desc.textContent = 'Adds a 6-digit authenticator code to every sign-in.';
      }
      // Fetch the device list once per sign-in, not on every state emit
      // (online-status flaps also fire onChange).
      if (sessionsFor !== state.user.id) {
        sessionsFor = state.user.id;
        loadSessions();
      }
    } else {
      sessionsFor = null;
      out.style.display = 'block';
      inn.style.display = 'none';
    }
  }

  // ── Signed-in devices ─────────────────────────────
  function browserFromUA(ua) {
    if (!ua) return 'Unknown device';
    let browser = 'Browser';
    if (/HeadlessChrome/i.test(ua)) browser = 'Chrome (headless)';
    else if (/Edg\//.test(ua)) browser = 'Edge';
    else if (/OPR\//.test(ua)) browser = 'Opera';
    else if (/Chrome\//.test(ua)) browser = 'Chrome';
    else if (/Firefox\//.test(ua)) browser = 'Firefox';
    else if (/Safari\//.test(ua)) browser = 'Safari';
    let os = '';
    if (/Macintosh/.test(ua)) os = 'macOS';
    else if (/Windows/.test(ua)) os = 'Windows';
    else if (/iPhone|iPad/.test(ua)) os = 'iOS';
    else if (/Android/.test(ua)) os = 'Android';
    else if (/Linux/.test(ua)) os = 'Linux';
    return os ? `${browser} on ${os}` : browser;
  }

  function relTime(iso) {
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }

  async function loadSessions() {
    const el = $('sessions-list');
    if (!el) return;
    let list;
    try {
      list = await SentinelAPI.listSessions();
    } catch {
      el.innerHTML = `<div style="color:var(--text-3);font-size:12px;padding:6px 0">Could not load sessions — server unreachable.</div>`;
      return;
    }
    el.innerHTML = list.map((s) => `
      <div class="session-row" data-family="${s.family_id}">
        <span class="session-icon"><svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg></span>
        <div class="session-info">
          <span class="session-device">${browserFromUA(s.user_agent)}${s.current ? ' <span class="alert-badge success" style="margin-left:6px">This device</span>' : ''}</span>
          <span class="session-meta">${s.ip_address || 'unknown IP'} · signed in ${relTime(s.created_at)} · active ${relTime(s.last_active)}</span>
        </div>
        ${s.current ? '' : `<button class="remove-btn session-revoke" data-family="${s.family_id}">Revoke</button>`}
      </div>
    `).join('') || `<div style="color:var(--text-3);font-size:12px;padding:6px 0">No active sessions.</div>`;

    el.querySelectorAll('.session-revoke').forEach((btn) => {
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        btn.textContent = 'Revoking…';
        try {
          await SentinelAPI.revokeSession(btn.dataset.family);
          showToast?.('Session revoked', 'success');
          loadSessions();
        } catch {
          showToast?.('Could not revoke session', 'danger');
          btn.disabled = false;
          btn.textContent = 'Revoke';
        }
      });
    });
  }

  // ── QR code (qrcode-generator, lazy-loaded) ───────
  function loadQrLib() {
    if (window.qrcode) return Promise.resolve();
    if (!qrLibLoading) {
      qrLibLoading = new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = 'https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js';
        s.onload = resolve;
        s.onerror = () => { qrLibLoading = null; reject(new Error('QR library failed to load')); };
        document.head.appendChild(s);
      });
    }
    return qrLibLoading;
  }

  function renderQr(uri) {
    const wrap = $('mfa-qr');
    wrap.innerHTML = '';
    const qr = window.qrcode(0, 'M');
    qr.addData(uri);
    qr.make();
    wrap.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 0 });
  }

  // ── MFA modal ─────────────────────────────────────
  const showErr = (msg) => { const e = $('mfa-modal-error'); e.textContent = msg; e.style.display = 'block'; };

  async function openMfaModal() {
    const enabled = SentinelAPI.currentUser()?.mfa_enabled;
    mfaMode = enabled ? 'disable' : 'enable';
    $('mfa-modal-title').textContent = enabled ? 'Disable Two-Factor Authentication' : 'Enable Two-Factor Authentication';
    $('mfa-modal-submit').textContent = enabled ? 'Verify & Disable' : 'Verify & Enable';
    $('mfa-enroll-step').style.display = enabled ? 'none' : 'block';
    $('mfa-disable-sub').style.display = enabled ? 'block' : 'none';
    $('mfa-modal-error').style.display = 'none';
    $('mfa-code-input').value = '';
    $('mfa-modal').classList.add('modal-open');

    if (!enabled) {
      $('mfa-qr').innerHTML = '<div class="spinner"></div>';
      try {
        const [enroll] = await Promise.all([SentinelAPI.mfaEnroll(), loadQrLib()]);
        $('mfa-secret').textContent = enroll.secret;
        renderQr(enroll.otpauth_uri);
      } catch (err) {
        showErr(err?.message || 'Could not start enrollment.');
        $('mfa-qr').innerHTML = '';
      }
    }
    setTimeout(() => $('mfa-code-input').focus(), 60);
  }

  function closeMfaModal() { $('mfa-modal').classList.remove('modal-open'); }

  async function submitMfaModal() {
    const code = $('mfa-code-input').value.trim();
    $('mfa-modal-error').style.display = 'none';
    if (code.length !== 6) { showErr('Enter the 6-digit code.'); return; }
    const btn = $('mfa-modal-submit');
    btn.disabled = true;
    try {
      if (mfaMode === 'enable') {
        await SentinelAPI.mfaEnable(code);
        showToast?.('Two-factor authentication enabled', 'success');
      } else {
        await SentinelAPI.mfaDisable(code);
        showToast?.('Two-factor authentication disabled', 'warn');
      }
      closeMfaModal();
    } catch (err) {
      showErr(err?.status === 400 ? 'Invalid code — try the current one from your app.' : (err?.message || 'Something went wrong.'));
    } finally {
      btn.disabled = false;
    }
  }

  // ── Wire up ───────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    if (!window.SentinelAPI) return;
    SentinelAPI.onChange(renderPanel);
    renderPanel(SentinelAPI.state);

    $('acct-signin-btn')?.addEventListener('click', () => $('account-signin')?.click());
    $('acct-mfa-btn')?.addEventListener('click', openMfaModal);
    $('mfa-modal-close')?.addEventListener('click', closeMfaModal);
    $('mfa-modal')?.addEventListener('click', (e) => { if (e.target.id === 'mfa-modal') closeMfaModal(); });
    $('mfa-modal-submit')?.addEventListener('click', submitMfaModal);
    $('mfa-code-input')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') submitMfaModal(); });
  });
})();
