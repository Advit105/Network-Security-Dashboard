// ═══════════════════════════════════════════════════
//  api.js — SentinelX backend client (phase 2)
//  Talks to the FastAPI auth/blocklist service. Cross-origin:
//    * every request sends cookies (credentials: 'include')
//    * the CSRF token comes from the auth response body / GET /auth/session
//      (the SPA can't read the API-origin cookie) and is echoed in a header
//      on all mutating requests.
//  Designed to degrade gracefully: if the backend is unreachable, the app
//  stays fully functional on localStorage (see blocklist.js).
// ═══════════════════════════════════════════════════

// Assigned onto window explicitly: top-level `const` in a classic script does
// not create a window property, and auth_ui.js gates on window.SentinelAPI.
window.SentinelAPI = (() => {
  'use strict';

  // Backend base URL. Override by setting window.SENTINEL_API_BASE before load.
  const BASE = (window.SENTINEL_API_BASE || 'http://localhost:8000/api/v1').replace(/\/$/, '');

  const state = {
    user: null,        // { id, email, role, mfa_enabled, ... } or null
    csrf: null,        // CSRF token string
    online: null,      // null = unknown, true/false = last known backend reachability
  };
  const listeners = new Set();
  const onChange = (fn) => { listeners.add(fn); return () => listeners.delete(fn); };
  const emit = () => listeners.forEach(fn => { try { fn(state); } catch {} });

  function isLoggedIn() { return !!state.user; }
  function currentUser() { return state.user; }

  async function request(method, path, body, { csrf = false, retry = true } = {}) {
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (csrf && state.csrf) headers['X-CSRF-Token'] = state.csrf;
    let res;
    try {
      res = await fetch(BASE + path, {
        method,
        credentials: 'include',
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (err) {
      // Network / CORS / backend down.
      state.online = false; emit();
      throw new ApiError(0, 'offline', 'Cannot reach the SentinelX server');
    }
    state.online = true;
    if (res.status === 204) return null;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      // Access token expired mid-session (TTL 15 min): rotate the refresh
      // token once and replay the request. Refresh itself passes retry:false.
      if (res.status === 401 && retry && state.user) {
        if (await tryRefresh()) return request(method, path, body, { csrf, retry: false });
        state.user = null; state.csrf = null; emit();   // session truly gone
      }
      throw new ApiError(res.status, data.detail || res.statusText, data.detail);
    }
    return data;
  }

  // Single-flight refresh: concurrent 401s share one rotation (a second
  // POST /auth/refresh with the same cookie would trip reuse detection).
  let refreshing = null;
  function tryRefresh() {
    if (!refreshing) {
      refreshing = request('POST', '/auth/refresh', undefined, { csrf: true, retry: false })
        .then((r) => { if (r && r.csrf_token) state.csrf = r.csrf_token; return true; })
        .catch(() => false)
        .finally(() => { refreshing = null; });
    }
    return refreshing;
  }

  class ApiError extends Error {
    constructor(status, detail, message) {
      super(typeof message === 'string' ? message : (Array.isArray(message) ? 'Validation failed' : detail || 'Error'));
      this.status = status; this.detail = detail;
    }
  }

  // ── Auth ──────────────────────────────────────────
  async function bootstrap() {
    // Called on page load: are we already logged in (cookie present)?
    try {
      let s = await request('GET', '/auth/session');
      if (s && !s.authenticated && s.csrf_token) {
        // Access token expired but the 7-day refresh cookie may still be
        // alive — rotate it and ask again instead of dumping the user out.
        state.csrf = s.csrf_token;
        if (await tryRefresh()) s = await request('GET', '/auth/session');
      }
      if (s && s.authenticated) {
        state.user = s.user; state.csrf = s.csrf_token;
      } else {
        state.user = null; state.csrf = null;
      }
    } catch {
      state.user = null; state.csrf = null;
    }
    emit();
    return state.user;
  }

  async function register(email, password) {
    return request('POST', '/auth/register', { email, password });
  }

  async function login(email, password) {
    const r = await request('POST', '/auth/login', { email, password });
    if (r.mfa_required) return { mfa_required: true, mfa_token: r.mfa_token };
    state.user = r.user; state.csrf = r.csrf_token; emit();
    return { mfa_required: false, user: r.user };
  }

  async function verifyMfa(mfaToken, code) {
    const r = await request('POST', '/auth/mfa/verify', { mfa_token: mfaToken, code });
    state.user = r.user; state.csrf = r.csrf_token; emit();
    return r.user;
  }

  async function logout() {
    try {
      await request('POST', '/auth/logout', undefined, { csrf: true, retry: false });
    } catch (err) {
      // Stale CSRF would leave the server session alive while the UI shows
      // signed-out — re-sync the token from /auth/session and retry once.
      if (err && err.status === 403) {
        try {
          const s = await request('GET', '/auth/session');
          if (s && s.csrf_token) {
            state.csrf = s.csrf_token;
            await request('POST', '/auth/logout', undefined, { csrf: true, retry: false });
          }
        } catch {}
      }
    }
    state.user = null; state.csrf = null; emit();
  }

  // ── MFA management (authenticated + CSRF) ─────────
  async function mfaEnroll() {
    return request('POST', '/auth/mfa/enroll', undefined, { csrf: true });
  }
  async function mfaEnable(code) {
    const r = await request('POST', '/auth/mfa/enable', { code }, { csrf: true });
    if (state.user) { state.user.mfa_enabled = true; emit(); }
    return r;
  }
  async function mfaDisable(code) {
    const r = await request('POST', '/auth/mfa/disable', { code }, { csrf: true });
    if (state.user) { state.user.mfa_enabled = false; emit(); }
    return r;
  }

  // ── Device sessions ───────────────────────────────
  async function listSessions() {
    const r = await request('GET', '/auth/sessions');
    return r.sessions;
  }
  async function revokeSession(familyId) {
    return request('DELETE', '/auth/sessions/' + encodeURIComponent(familyId), undefined, { csrf: true });
  }

  // ── Blocklist resource ────────────────────────────
  async function listBlocklist() {
    return request('GET', '/blocklist');
  }
  async function addBlocklist(ip, reason, severity) {
    return request('POST', '/blocklist', { ip, reason, severity }, { csrf: true });
  }
  async function removeBlocklist(id) {
    return request('DELETE', '/blocklist/' + encodeURIComponent(id), undefined, { csrf: true });
  }

  return {
    BASE, state, onChange, isLoggedIn, currentUser,
    bootstrap, register, login, verifyMfa, logout,
    mfaEnroll, mfaEnable, mfaDisable,
    listSessions, revokeSession,
    listBlocklist, addBlocklist, removeBlocklist,
    ApiError,
  };
})();
