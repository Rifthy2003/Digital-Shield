# MVP Implementation Checklist

Status as of this build. "Implemented" means: real backend logic exists,
is covered by at least one passing automated test, is exposed through a
real API route, and (where applicable) has a connected frontend page —
not a mockup.

## A. Authentication & User Management
- [x] Registration (email + Argon2id password hash)
- [x] Login with account lockout after repeated failures
- [x] Logout (refresh token revocation)
- [x] JWT access tokens + rotating, hashed refresh tokens
- [x] RBAC (citizen / admin) enforced via a single dependency
- [ ] Password reset workflow (schemas exist, route not yet built)
- [ ] MFA enrollment (data model exists, UI/flow not built)
- [x] `/auth/me` profile endpoint + frontend Profile page

## B. Security Dashboard
- [x] Live, explainable security score (not simulated)
- [x] Score breakdown with per-factor reasons
- [x] Critical/medium/informational alert counts
- [x] Recent activity feed
- [x] Recommendations generated from actual gaps in the score
- [x] All figures are clearly real/live — `demo_data_notice` field exists
      specifically so the frontend could flag simulated data, and is
      `null` everywhere because nothing here is simulated

## C. URL Threat Checker
- [x] HTTPS check, certificate validity check
- [x] Redirect chain analysis
- [x] IP-literal / punycode / subdomain-depth heuristics
- [x] Pluggable domain-reputation hook (honestly marked `not_evaluated`
      when no provider is wired in — none is, in this build)
- [x] Documented, fixed-weight scoring methodology (see `url_analysis.py`
      module docstring)
- [x] SSRF protections, tested against localhost/private-range/metadata/
      disallowed-scheme targets

## D. Scam & Phishing Message Analyzer
- [x] Urgency, financial-request, impersonation, credential-request,
      generic-greeting, and link-presence detection
- [x] Documented scoring methodology
- [x] Raw message content never persisted — only a hash
- [x] Response always carries a "not a guarantee" disclaimer

## E. Email Breach Monitoring
- [x] Provider interface with an explicit `UnconfiguredBreachProvider`
- [x] Honest "not configured" response when no `HIBP_API_KEY` is set
      (verified by test) — never a fabricated result
- [x] Real HIBP integration code path exists and is ready once a key is
      supplied, but was not exercised against the live API in this build
      (no network access to haveibeenpwned.com from the build sandbox)

## F. Password Security
- [x] Local strength analysis (length, character variety, common-password list)
- [x] Password never stored, logged, or echoed back (verified by test)
- [x] k-anonymity hash-splitting helper ready for a Pwned-Passwords-style check

## G. Security Alerts
- [x] Alert creation from URL/message/breach findings
- [x] Severity levels (high/medium/info)
- [x] Read/resolved status, per-user scoping
- [x] Frontend Alerts page with mark-read / resolve actions

## H. Security Recommendations
- [x] Derived directly from the score breakdown, not a separate static list

## I. Citizen Cyber Incident Reporting
- [x] Submission with category + description
- [x] Report ID generation, status tracking
- [x] Per-user isolation (verified by query filter, not yet IDOR-fuzz-tested)
- [x] Clear "not a replacement for official reporting" disclaimer in UI and API
- [ ] Evidence file upload (schema column exists, upload endpoint does not)

## J. AI Cybersecurity Assistant
- [x] Chat interface
- [x] Rule-based fallback grounded in the real URL/message analyzers
- [x] Explicit "not configured" / fallback-mode labeling — never pretends
      an AI provider answered when none is set
- [ ] Real external AI provider integration (interface point exists in
      `ai_assistant.py`, deliberately left as a visible placeholder rather
      than faked)

## K. Admin Dashboard
- [x] Aggregate platform statistics (user count, check counts, report counts)
- [x] Incident report queue
- [x] Individual-record access is separate from aggregate views and is
      audit-logged on every call
- [x] Role-escalation test confirms non-admins are rejected

## Cross-cutting
- [x] Rate limiting on auth, scanning, and AI endpoints
- [x] Security headers on every response
- [x] Audit logging for registration, login, logout, and admin
      individual-record views
- [x] 30 automated backend tests, all passing
- [x] Frontend builds cleanly with no TypeScript errors
- [ ] CI pipeline
- [ ] Independent security review / formal OWASP Top 10 pass
- [ ] Docker Compose stack verified against a real Docker daemon

See `docs/ROADMAP.md` for everything intentionally out of scope for this
MVP (OAuth integrations, device/login monitoring, Privacy Center, Smart
Message Protection, enterprise multi-tenancy, government dashboard,
multi-country support).
