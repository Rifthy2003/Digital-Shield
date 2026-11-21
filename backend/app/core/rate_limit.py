"""
Application-wide rate limiting, keyed by client IP. Individual routes
override the default limit (e.g. stricter limits on auth and scan
endpoints) via the `@limiter.limit(...)` decorator.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
