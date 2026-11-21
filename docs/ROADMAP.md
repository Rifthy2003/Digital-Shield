# Roadmap — what's next

This MVP deliberately stops short of several features in the original
concept brief, per the development rule "do not implement advanced
integrations without verifying official API capabilities." Each item below
notes why it's not in this build and what verifying it would involve.

## Immediate next steps (same MVP, not yet done)

- [ ] CI pipeline (lint + test + build on every push)
- [ ] Incident evidence file upload (endpoint, validation, storage, virus scan)
- [ ] MFA enrollment UI (TOTP QR code + verification) — backend columns exist
- [ ] Email delivery (verification emails, password reset emails — the
      endpoints exist conceptually but no email provider is wired in)
- [ ] Password reset flow (`PasswordResetRequest`/`PasswordResetConfirm`
      schemas exist in `schemas/auth.py` but have no route yet)
- [ ] Full OWASP Top 10 review by someone other than the implementer
- [ ] Verify the Docker Compose stack against a real Docker daemon
      (written and reviewed, not executed, in this build environment)

## Phase: OAuth & Digital Account Integrations

**Not started.** Before any code: research exactly what Google, Microsoft,
Meta, LinkedIn, and Apple's OAuth APIs expose to third-party apps for
login/device/session data — most consumer identity providers expose little
to none of this. The `OAuthToken` model concept (encrypted at rest, keys
outside the app database) is documented in `SECURITY.md` but not yet
implemented; do not build it only to end up with a feature that redirects
to the provider's own page anyway. Build the feasibility matrix first.

## Phase: Device & Login Activity Monitoring

**Blocked on the above.** Only meaningful once an OAuth integration exists
and that provider's API has been confirmed to expose session data.

## Phase: Privacy Center

**Not started.** Requires a native mobile app (Android/iOS) or browser
extension to read permission state — this is not buildable as part of the
current web-only MVP. Scope per-platform before writing any code: Android's
permission APIs are far more open than iOS's.

## Phase: Smart Message Protection

**Not started.** No general API exists on iOS or Android to read SMS/
WhatsApp content automatically. The realistic feature is a "share to
Infora" intent handler (Android) and an iOS Messages Filter extension
(SMS-only, no WhatsApp). Do not build anything that implies broader access
than that.

## Phase: Enterprise Multi-Tenant Support

**Not started.** The `User.role` enum currently has two values
(`citizen`, `admin`); an `org_admin` / tenant model would need its own
schema design, with tenant isolation tested as rigorously as the
per-user ownership checks in this MVP. The hard requirement from the
concept brief — org-admins must never reach an employee's personal
accounts — needs to be a test, not just a promise, before this ships.

## Phase: Government Dashboard

**Not started.** Requires (a) enough real incident-report volume to
aggregate meaningfully, (b) a k-anonymity threshold design so no small
bucket re-identifies someone, and (c) an actual legal review of any
government data-sharing arrangement. None of these exist yet; building the
UI first would be building ahead of the thing that makes it safe.

## Multi-country architecture

Not started. The incident categories, disclaimers, and scoring logic are
currently written generically (not Sri-Lanka-specific or UAE-specific), so
adding a per-country config layer (official domain directory, emergency
contacts, language) later should not require rewriting the modules above —
but that config layer itself doesn't exist yet.
