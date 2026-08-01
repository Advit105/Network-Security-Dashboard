// ═══════════════════════════════════════════════════
//  gauth.js — Google sign-in (Firebase Auth) + per-user
//  blocklist sync (Firestore). ES module, no build step.
//
//  Coexists with the email/password path (api.js). Data routing is decided
//  in blocklist.js by whichever session is active:
//     Google user → this module's `store` (Firestore)
//     email user  → SentinelAPI (FastAPI backend)
//     neither     → localStorage (guest)
//
//  Fail-safe: if firebase-config.js still holds placeholders, Google sign-in
//  is disabled and the app keeps working in guest mode.
// ═══════════════════════════════════════════════════
import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js';
import {
  getAuth, GoogleAuthProvider, signInWithPopup, signOut, onAuthStateChanged,
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js';
import {
  getFirestore, collection, addDoc, deleteDoc, doc, onSnapshot,
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js';

const GUEST_KEY = 'sentinelx_blocklist_guest';   // shared with auth_ui.js
const DISPLAY_KEY = 'sentinelx_blocklist';
const $ = (id) => document.getElementById(id);
const cfg = window.FIREBASE_CONFIG || {};
const configured = cfg.apiKey && !String(cfg.apiKey).includes('TODO');

// ── Not configured yet: expose a stub + hint on the Google button ──
if (!configured) {
  window.GAuth = { configured: false, isSignedIn: () => false };
  $('auth-google')?.addEventListener('click', () => {
    (window.showToast || (() => {}))('Google sign-in isn’t configured yet — see README.md', 'warn');
  });
} else {
  const app = initializeApp(cfg);
  const auth = getAuth(app);
  const db = getFirestore(app);
  const provider = new GoogleAuthProvider();

  let currentUser = null;
  let synced = false;

  // ── Firestore blocklist store — same shape SentinelAPI exposes, so
  //    blocklist.js treats both identically. Path: users/{uid}/blocklist ──
  const store = {
    async addBlocklist(ip, reason, severity) {
      const created_at = new Date().toISOString();
      const ref = await addDoc(collection(db, 'users', currentUser.uid, 'blocklist'),
        { ip, reason, severity, created_at });
      return { id: ref.id, ip, reason, severity, created_at };
    },
    async removeBlocklist(id) {
      await deleteDoc(doc(db, 'users', currentUser.uid, 'blocklist', id));
    },
  };

  // ── Guest ↔ cloud snapshot (mirrors auth_ui.js so both auth paths agree) ──
  const backupGuest = () => localStorage.setItem(GUEST_KEY, localStorage.getItem(DISPLAY_KEY) || '[]');
  function restoreGuest() {
    localStorage.setItem(DISPLAY_KEY, localStorage.getItem(GUEST_KEY) || '[]');
    localStorage.removeItem(GUEST_KEY);
    window.refreshBlocklistViews?.();
  }
  // ── Account widget (shares the DOM with auth_ui.js) ──
  function renderAccount(user) {
    const signin = $('account-signin'), info = $('account-info');
    if (!signin || !info) return;
    if (user) {
      signin.style.display = 'none';
      info.style.display = 'flex';
      info.setAttribute('data-tip', user.email || 'Google account');
      $('account-avatar').textContent = (user.email?.[0] || user.displayName?.[0] || 'G').toUpperCase();
      $('account-email').textContent = user.email || user.displayName || 'Google account';
      const st = $('account-status');
      st.textContent = 'Synced'; st.className = 'account-status';
      $('auth-modal')?.classList.remove('modal-open'); // close modal after popup
    } else {
      signin.style.display = 'flex';
      info.style.display = 'none';
    }
  }

  async function signIn() {
    try { await signInWithPopup(auth, provider); }
    catch (e) {
      console.error('Google sign-in failed:', e);
      (window.showToast || (() => {}))('Google sign-in failed: ' + (e.code || e.message), 'danger');
    }
  }
  const doSignOut = () => signOut(auth).catch(() => {});

  let unsub = null;
  onAuthStateChanged(auth, (user) => {
    currentUser = user;
    renderAccount(user);
    if (user && !synced) {
      synced = true;
      backupGuest();
      // Live: any change to users/{uid}/blocklist — this tab, another tab, or
      // another device — pushes straight into the display. No manual refresh.
      unsub = onSnapshot(collection(db, 'users', user.uid, 'blocklist'),
        (snap) => window.setBlocklistFromServer?.(snap.docs.map(d => ({ id: d.id, ...d.data() }))),
        (err) => console.warn('Firestore listen failed:', err));
    } else if (!user && synced) {
      synced = false;
      if (unsub) { unsub(); unsub = null; }
      restoreGuest();
    }
  });

  window.GAuth = {
    configured: true,
    isSignedIn: () => !!currentUser,
    user: () => currentUser,
    signIn,
    signOut: doSignOut,
    store,
  };

  $('auth-google')?.addEventListener('click', signIn);
}
