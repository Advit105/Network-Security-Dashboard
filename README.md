# SentinelX

A security operations dashboard that runs on real, live data — no simulations, no seeded demo content.

## Features

- **Top Threat Origins** — geolocates every IP in your blocklist (via ipwho.is) and ranks the origin countries by count.
- **Log Analyzer** — paste raw logs; suspicious patterns are parsed, public IPs are extracted, geolocated, and can be bulk-blocked.
- **IP Lookup** — geolocation, ISP, and exposure data (Shodan InternetDB) for any address.
- **DNS Lookup** — live records via Google DNS-over-HTTPS.
- **Blocklist Manager** — per-account blocklist that syncs across devices when signed in (Google or email); works fully offline as a guest (localStorage). Export to **iptables / pf / Cisco ACL / CSV / STIX 2.1**.
- **Investigation Cases** — group the IPs, domains, hashes and notes from an investigation into named cases; synced to your account (Google) or kept local as a guest.
- **Hash Generator / Password Checker** — Web Crypto API hashing, entropy analysis, and breach checks.
- **CVE Live Feed** — latest vulnerabilities from the NVD.
- **SSL/TLS Inspector** — Certificate Transparency lookups via crt.sh.
- **Email Security Checker** — live SPF/DMARC/DKIM/MX/DNSSEC audit for any domain via DNS-over-HTTPS.
- **Accounts** — sign in with Google (Firebase, no backend needed) or self-host the Argon2id + TOTP MFA backend for email/password auth.
- **AbuseIPDB** — IP reputation (bring your own free API key).
- **Typosquat Scanner** — generates look-alike domains and resolves them live to find registered impersonators.

## Layout

```
index.html    — landing page (terminal-style gate into the console)
app.html      — the single-page app shell
css/          — stylesheets (app design tokens + landing theme)
js/           — one module per feature (api client, auth UI, tools…)
js/gauth.js   — Google sign-in (Firebase Auth) + Firestore blocklist sync
firebase-config.js — your public Firebase web config (fill in to enable Google)
firestore.rules    — per-user Firestore security rules
serve.py      — dev static server with correct cache headers
backend/      — FastAPI auth + sync service (optional, self-host only)
```

## Running

Frontend — use the bundled server (it disables HTML caching so changes always show up):

```sh
python3 serve.py          # http://localhost:8741
```

Backend (accounts + blocklist sync) — FastAPI + PostgreSQL:

```sh
cd backend
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-server-header
```

See [backend/README.md](backend/README.md) for database setup, configuration, and the security architecture, and [backend/SECURITY.md](backend/SECURITY.md) for the threat model.

The app is fully functional without the backend — accounts and cross-device sync simply switch off and the blocklist stays local.

## Google sign-in (serverless, GitHub Pages–ready)

The app can sync each user's blocklist to their own Google account via Firebase
Auth + Firestore — **no backend to run**. This is what makes it deployable to
GitHub Pages for anyone to use. One-time setup:

1. **Create a Firebase project** at <https://console.firebase.google.com>.
2. **Add a Web app** (`</>`), copy the generated config object, and paste its
   values into [js/firebase-config.js](js/firebase-config.js). *(This config is
   public by design — it's safe to commit. Security comes from the rules below,
   not from hiding it.)*
3. **Authentication → Sign-in method →** enable **Google**.
4. **Firestore Database → Create** (Production mode), then **Rules →** paste
   [firestore.rules](firestore.rules) and Publish. Each user can then read/write
   only their own data.
5. **Authentication → Settings → Authorized domains →** add your Pages domain
   (e.g. `your-username.github.io`) and `localhost` for local testing.

Until step 2 is done, Google sign-in stays disabled and the app runs in guest
mode — nothing breaks.

### App Check (recommended once public)

Your web config is public, so anyone could point their own page at your Firebase
project. **App Check** (reCAPTCHA v3) makes Firebase reject requests that don't
come from your app. To enable:

1. Firebase console → **App Check** → register your Web app with the
   **reCAPTCHA v3** provider; copy the **site key**.
2. Put it in [js/firebase-config.js](js/firebase-config.js) as
   `window.APPCHECK_SITE_KEY`. (Leaving the placeholder keeps App Check off.)
3. Test the live site — sign-in and Firestore should still work (tokens now
   attach automatically).
4. **Only then**, in App Check, set Firestore + Authentication to **Enforce**.
   Enforcing *before* the site key is live would lock the app out.

> Local dev needs an App Check **debug token** (console → App Check → your app →
> Manage debug tokens) set via `self.FIREBASE_APPCHECK_DEBUG_TOKEN` — or just
> test App Check on the deployed site.

### Deploy to GitHub Pages

The frontend is static, so Pages serves it directly:

```sh
git push                     # push this repo to GitHub
```

Then **Settings → Pages → Source: Deploy from branch → `main` / root**. Your app
goes live at `https://<user>.github.io/<repo>/app.html`. Add that domain under
Firebase Authorized domains (step 5) so Google sign-in works there.

> The FastAPI backend (email/password + MFA) can't run on Pages — that path is
> for self-hosting only. Google sign-in + Firestore covers the hosted version.

## Installable app, offline & hardening

- **PWA** — [manifest.json](manifest.json) + [sw.js](sw.js) make it installable (Chrome/Edge show an "Install app" button; iOS: Share → Add to Home Screen) and fast on repeat visits. The service worker caches the app shell for offline use but **never caches cross-origin/API responses**, so live data stays live.
- **Real-time sync** — a signed-in user's blocklist updates live across tabs and devices via a Firestore `onSnapshot` listener.
- **Content-Security-Policy** — a strict CSP ships in the `<head>` of both pages (no `unsafe-inline` for scripts). All UI actions use delegated listeners + `data-*` attributes instead of inline `onclick`.
  - *Self-hosting the FastAPI backend?* The CSP allows `http://localhost:8000` for local dev. If your backend runs on a different origin, add it to the `connect-src` directive in [app.html](app.html).
- **Accessibility** — dialogs use `role="dialog"` + focus trap/restore; `prefers-reduced-motion` disables animation and page cross-fades.
- **CI** — [.github/workflows/ci.yml](.github/workflows/ci.yml) syntax-checks every JS file, validates the manifest/config, and fails the build if an inline event handler (which the CSP forbids) sneaks back in.

## Stack

Vanilla HTML/CSS/JS single-page app (no build step) · FastAPI · PostgreSQL · Argon2id · TOTP MFA.
