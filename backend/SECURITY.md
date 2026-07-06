# Security & Incident Response

## Reporting a vulnerability
Email security@your-domain.example with details and reproduction steps. Do not open
a public issue for undisclosed vulnerabilities. We aim to acknowledge within 48h.

## What we log (and what we never log)
The `audit_logs` table records: event type, user id (when known), email, IP, user
agent, a free-text detail, and a `suspicious` flag. We **never** log passwords,
password hashes, MFA secrets, MFA codes, JWTs, refresh tokens, or reset tokens.

## Signals to alert on
| Signal | Query shape | Likely meaning |
|---|---|---|
| Burst of `login_failure` for one email | group by email, window 15m | Credential brute force |
| `login_failure` across many emails from one IP | group by ip | Credential stuffing |
| `login_locked` | any | Account under active attack |
| `token_reuse_detected` | any | Stolen refresh token replayed |
| `mfa_failure` repeats | group by user | MFA bypass attempt |
| `login_success` from a new country for a user | compare geo to history | Account takeover |

Wire these to your alerting (e.g. a scheduled query → PagerDuty/Slack). The
`suspicious=true` rows are pre-flagged for a first-pass alert.

## Incident response runbook (abridged)
1. **Detect** — alert fires or a report arrives.
2. **Triage** — classify severity; identify affected accounts via `audit_logs`.
3. **Contain**
   - Force-logout a user: revoke all their sessions (delete/revoke rows in
     `sessions` for that `user_id`) — access dies within the 15-min token TTL,
     refresh dies immediately.
   - Lock an account: set `locked_until` in the future.
   - Global: rotate `JWT_SECRET` (invalidates all access tokens) and/or revoke all
     sessions.
4. **Eradicate** — patch the root cause; if a secret leaked, rotate `JWT_SECRET`,
   `FERNET_KEY` (re-encrypt MFA secrets), and DB credentials.
5. **Recover** — restore normal operation; require password reset for affected users.
6. **Post-mortem** — document timeline from `audit_logs`; add a detection/test.

## Secret rotation notes
- `JWT_SECRET`: rotating invalidates all outstanding access tokens (users re-auth).
- `FERNET_KEY`: rotating requires re-encrypting stored MFA secrets; plan a migration
  (decrypt-with-old → encrypt-with-new) before swapping the key.
- DB credentials: rotate in the environment/secret store; never in source.

## Dependency & supply-chain hygiene
- Pin versions in `requirements.txt` (done). Run `pip-audit` in CI.
- Enable Dependabot / renovate for patch updates.
- Verify webhook signatures for any future integrations; use PKCE for OAuth.
