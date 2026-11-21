# Security

## Credential handling

- **Infora account passwords**: hashed with Argon2id (`app/core/security.py`).
  No plaintext password is ever stored, logged, or returned in any API
  response. Verified by `tests/test_auth.py` (registration response
  contains neither `password` nor `password_hash`) and
  `tests/test_password_and_message.py` (the strength-check endpoint never
  echoes the submitted password back).
- **Refresh tokens**: random 64-byte tokens; only their SHA-256 hash is
  persisted (`RefreshToken.token_hash`). A database read alone cannot
  produce a usable session. Tokens rotate on every refresh and are revoked
  on logout — verified by `test_refresh_token_rotation` and
  `test_logout_revokes_refresh_token`.
- **Third-party account passwords**: never collected, in the MVP or the
  planned OAuth future work. Only official OAuth flows are planned; see
  `docs/ROADMAP.md`.
- **Password strength / breach checks**: the password itself is analyzed
  in-memory for the one request and never stored
  (`services/password_strength.py`). The k-anonymity split helper
  (`k_anonymity_prefix`) is in place for a future Pwned-Passwords-style
  check so a full password hash never needs to leave the server either.

## SSRF protection (URL Threat Checker)

`services/ssrf_guard.py` resolves the target hostname and rejects any
address that is private, loopback, link-local, multicast, reserved, or a
known cloud metadata endpoint (`169.254.169.254`, etc.) **before** the
first request is made. The same validation runs again on every redirect
hop inside `services/url_analysis.py`, specifically to defend against DNS
rebinding (a safe hostname at validation time resolving to an internal
address at request time). Covered by `tests/test_url_checker.py`
(`test_ssrf_guard_blocks_*`).

## Data minimization

- **Message analyzer**: only a SHA-256 hash of submitted message content is
  persisted (`MessageCheck.content_hash`); the raw text lives only in
  memory for the duration of the request. Verified by
  `test_message_checker_api_never_stores_raw_text`.
- **URL checker**: similarly, only a hash of the normalized URL is stored
  for anonymous/history purposes, not a reversible copy beyond what's
  needed for caching/dedup.
- **Breach checker**: only a hash of the email is stored alongside the
  verdict, never the email in a form intended for bulk export.

## Honesty over fabrication

Three features are explicitly allowed to degrade rather than lie, per the
development rules this build followed:

1. **Breach monitoring** (`services/breach_provider.py`) returns
   `configured: false` and a clear message when `HIBP_API_KEY` is unset —
   never a fabricated "no breaches found."
2. **AI Assistant** (`api/routes/ai_assistant.py`) runs a rule-based
   fallback grounded in the platform's own URL/message analyzers when
   `AI_PROVIDER_API_KEY` is unset — it never pretends an external model
   answered.
3. **URL risk scoring** marks any indicator it could not evaluate (e.g. no
   reputation provider configured) as `not_evaluated: true` in the
   response rather than silently treating it as "safe."

## RBAC and data isolation

- Every protected route resolves the acting user from the JWT via
  `core/rbac.get_current_user` — route handlers never trust a user ID
  passed in a request body or query string.
- Alerts and incident reports are scoped to `user_id` ownership on every
  read (`_get_owned_alert` in `alerts.py`; the `user_id` filter in
  `incidents.py`). Verified conceptually by the admin-route test
  (`test_non_admin_cannot_reach_admin_routes`); a full cross-user IDOR
  fuzzing pass was not added this round — flagged in `MVP_CHECKLIST.md`.
- Admin endpoints (`api/routes/admin.py`) distinguish aggregate statistics
  (no audit needed) from individual-record views (`/admin/users/{id}`),
  which are logged via `record_audit_event` on every call, per the
  "admins cannot silently browse citizen data" requirement.

## Rate limiting

`slowapi` enforces per-IP limits: 10/minute on register and login
(brute-force resistance), 20/minute on the URL/message checkers and AI
assistant (abuse/automation resistance), 30/minute on the stateless
password-strength check. Limits are declared per-route in each router file,
not globally, so they can be tuned per endpoint's actual risk.

## Security headers

Set globally in `app/main.py`: `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`,
a baseline `Content-Security-Policy`, and HSTS when `ENVIRONMENT=production`.
The frontend's nginx config sets the same first three for static assets.

## What was NOT done this pass (be aware before any real deployment)

- **No independent penetration test.** The test suite covers the specific
  attack classes named in the task list (brute force, token replay, SSRF,
  IDOR-by-design via ownership filters) but is not a substitute for an
  OWASP Top 10 review by someone other than the author, as called for in
  Phase 16 of the task list.
- **No automated dependency/CVE scanning** wired into CI yet (no CI exists
  yet — see `ROADMAP.md`).
- **No MFA enrollment flow** implemented, though the `User.mfa_enabled` /
  `mfa_secret_encrypted` columns and the Security Score's MFA factor exist
  and are ready for it.
- **File upload handling for incident evidence** is referenced in the
  `IncidentReport.evidence_file_path` column but the actual upload
  endpoint, virus scanning, and storage backend were not implemented this
  pass — the task list's Task 13.1.4 is still open.
- **`datetime.utcnow()` deprecation** — see `ARCHITECTURE.md`.
