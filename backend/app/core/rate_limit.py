"""
Application-wide rate limiting, keyed by client IP. Individual routes
override the default limit (e.g. stricter limits on auth and scan
endpoints) via the `@limiter.limit(...)` decorator.

Trusted Proxy Security (SEC-02 / SEC-07):
Delegates client IP resolution to `app.core.client_ip.get_client_ip` so rate
limiting, device metadata, session records, and audit logs all share a single
trusted-proxy CIDR and X-Forwarded-For trust-boundary implementation.
"""
from slowapi import Limiter

from app.core.client_ip import get_client_ip

limiter = Limiter(key_func=get_client_ip)
