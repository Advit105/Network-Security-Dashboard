// ═══════════════════════════════════════════════════
//  firebase-config.js — public Firebase web config.
//
//  This is NOT a secret. Firebase web config is designed to ship in client
//  code; access is controlled by Firestore security rules + Auth, never by
//  hiding these values. Safe to commit to a public repo.
//
//  ── ONE-TIME SETUP (see README.md "Google sign-in") ──
//    1. Create a project at https://console.firebase.google.com
//    2. Add a Web app → copy its config object over the values below.
//    3. Build → Authentication → Sign-in method → enable Google.
//    4. Build → Firestore Database → create → paste firestore.rules.
//    5. Authentication → Settings → Authorized domains → add your GitHub
//       Pages domain (e.g. <user>.github.io) and localhost.
//
//  Until real values are filled in, Google sign-in stays disabled and the
//  app runs in guest / localStorage mode exactly as before.
// ═══════════════════════════════════════════════════
window.FIREBASE_CONFIG = {
  apiKey: "AIzaSyBzkPPPuSQkWQ-7uUhSMANeuBjuIyaFr2Y",
  authDomain: "sentinelx-105.firebaseapp.com",
  projectId: "sentinelx-105",
  storageBucket: "sentinelx-105.firebasestorage.app",
  messagingSenderId: "21533746472",
  appId: "1:21533746472:web:65b3e712799219d6ce9c1d",
  measurementId: "G-JNTJY5HQTH",
};

// ── Firebase App Check (optional, recommended for the public deploy) ──
// A reCAPTCHA v3 site key locks Firebase so only YOUR app can use the project
// (stops randoms from draining your quota with your public config). Left as a
// placeholder = App Check disabled and nothing breaks. See README "App Check".
window.APPCHECK_SITE_KEY = "TODO-RECAPTCHA-V3-SITE-KEY";
