"""
SSRF (Server-Side Request Forgery) protection for the URL threat checker.

The URL checker fetches user-submitted URLs. Without safeguards, that makes
the backend a proxy an attacker could use to probe internal infrastructure
(cloud metadata endpoints, internal services, localhost). This module
resolves the hostname and rejects anything that points at a private,
loopback, link-local, or otherwise non-public address BEFORE any request is
made, and again on every redirect hop.
"""
import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_SCHEMES = {"file", "ftp", "gopher", "data"}
ALLOWED_SCHEMES = {"http", "https"}

# Cloud metadata endpoints — must never be reachable via the scanner.
EXTRA_BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal"}


class UnsafeUrlError(ValueError):
    pass


def _is_private_or_reserved(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_url_is_safe_to_fetch(url: str) -> str:
    """
    Validates a user-submitted URL before it is fetched. Returns the
    normalized hostname on success, or raises UnsafeUrlError.

    Call this again after following each redirect — a safe initial host can
    redirect to an internal address.
    """
    parsed = urlparse(url)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeUrlError(f"Scheme '{parsed.scheme}' is not allowed; only http/https are permitted")

    hostname = parsed.hostname
    if not hostname:
        raise UnsafeUrlError("URL has no resolvable hostname")

    if hostname.lower() in EXTRA_BLOCKED_HOSTS:
        raise UnsafeUrlError("This host is not permitted to be scanned")

    # Resolve all addresses for the hostname and reject if ANY resolve to a
    # private/reserved range (defends against DNS rebinding).
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"Could not resolve hostname: {exc}") from exc

    if not addr_infos:
        raise UnsafeUrlError("Hostname did not resolve to any address")

    for family, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            is_unsafe = _is_private_or_reserved(ip_str)
        except ValueError as exc:
            raise UnsafeUrlError(f"Could not parse resolved IP address: {exc}") from exc
        if is_unsafe:
            raise UnsafeUrlError("Resolved address is in a private/reserved range and cannot be scanned")

    return hostname
