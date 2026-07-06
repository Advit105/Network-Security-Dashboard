# SentinelX

A security operations dashboard that runs on real, live data — no simulations, no seeded demo content.

## Features

- **Threat Origin Map** — geolocates every IP in your blocklist (via ipwho.is) and plots it on a real Natural Earth world map.
- **Log Analyzer** — paste raw logs; suspicious patterns are parsed, public IPs are extracted, geolocated, and can be bulk-blocked.
- **IP Lookup** — geolocation, ISP, and exposure data (Shodan InternetDB) for any address.
- **DNS Lookup** — live records via Google DNS-over-HTTPS.
- **Blocklist Manager** — per-account blocklist that syncs across devices when signed in; works fully offline as a guest (localStorage).
- **Hash Generator / Password Checker** — Web Crypto API hashing, entropy analysis, and breach checks.
- **CVE Live Feed** — latest vulnerabilities from the NVD.
- **SSL/TLS Inspector** — Certificate Transparency lookups via crt.sh.
- **Email Security Checker** — live SPF/DMARC/DKIM/MX/DNSSEC audit for any domain via DNS-over-HTTPS.
- **Accounts** — Argon2id auth with TOTP two-factor enrollment and per-device session management.
- **AbuseIPDB** — IP reputation (bring your own free API key).
- **Typosquat Scanner** — generates look-alike domains and resolves them live to find registered impersonators.

## Layout

```
index.html    — landing page (terminal-style gate into the console)
app.html      — the single-page app shell
css/          — stylesheets (app design tokens + landing theme)
js/           — one module per feature (api client, auth UI, tools, map…)
serve.py      — dev static server with correct cache headers
backend/      — FastAPI auth + sync service
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

## Stack

Vanilla HTML/CSS/JS single-page app (no build step) · FastAPI · PostgreSQL · Argon2id · TOTP MFA.
