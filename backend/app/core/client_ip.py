"""
Centralized, spoofing-resistant client IP resolution (SEC-07).

Trust-Boundary Strategy for X-Forwarded-For:
1. Inspect the immediate TCP peer address (`request.client.host`).
2. If the immediate peer is NOT in the explicitly configured `TRUSTED_PROXIES`
   (IPs, CIDR ranges, or non-production local test identifiers), ignore all
   forwarded headers (`X-Forwarded-For`, `X-Real-IP`) and return the peer IP.
3. If the immediate peer IS a trusted proxy:
   - Parse `X-Forwarded-For` from RIGHT to LEFT.
   - Validate every hop with Python's `ipaddress` module.
   - Skip hops that belong to `TRUSTED_PROXIES` (our own proxy chain).
   - Return the FIRST untrusted valid IP encountered from the right — this is
     the trust boundary (the client IP observed by our outermost trusted proxy).
     Any client-spoofed IPs prepended to the left of the trust boundary are ignored.
   - If a malformed or empty segment is encountered while walking right-to-left,
     stop immediately and fall back to the immediate peer IP so spoofed prefixes
     cannot be smuggled past malformed entries.
   - If `X-Forwarded-For` is absent or empty, fall back to `X-Real-IP` (validated
     via `ipaddress`), and finally to the immediate peer IP.
"""
import ipaddress
import logging
from functools import lru_cache
from typing import Iterable

from fastapi import Request

from app.config import get_settings

logger = logging.getLogger(__name__)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_NON_PROD_LITERAL_PEERS = {"testclient"}


@lru_cache(maxsize=16)
def _compile_trusted_proxies(
    entries: tuple[str, ...],
    is_production: bool,
) -> tuple[tuple[IPNetwork, ...], frozenset[str]]:
    """Compile configured trusted proxy entries into IP networks and literal hostnames."""
    networks: list[IPNetwork] = []
    literals: set[str] = set()

    for raw in entries:
        entry = raw.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
            continue
        except ValueError:
            pass

        lowered = entry.lower()
        if is_production and lowered in _NON_PROD_LITERAL_PEERS:
            continue
        literals.add(lowered)

    return tuple(networks), frozenset(literals)


def _get_compiled_proxies(
    trusted_proxies: Iterable[str] | None = None,
) -> tuple[tuple[IPNetwork, ...], frozenset[str]]:
    settings = get_settings()
    is_production = settings.ENVIRONMENT.strip().lower() == "production"
    entries = tuple(trusted_proxies) if trusted_proxies is not None else tuple(settings.TRUSTED_PROXIES)
    return _compile_trusted_proxies(entries, is_production)


def _is_ip_in_networks(ip_obj: IPAddress, networks: tuple[IPNetwork, ...]) -> bool:
    return any(ip_obj.version == net.version and ip_obj in net for net in networks)


def _is_trusted_peer(
    peer_host: str,
    networks: tuple[IPNetwork, ...],
    literals: frozenset[str],
) -> bool:
    try:
        peer_ip = ipaddress.ip_address(peer_host)
        return _is_ip_in_networks(peer_ip, networks)
    except ValueError:
        return peer_host.lower() in literals


def _normalize_peer(peer_host: str) -> str:
    try:
        return str(ipaddress.ip_address(peer_host))
    except ValueError:
        return peer_host


def _parse_x_forwarded_for(
    xff_header: str,
    fallback_peer: str,
    networks: tuple[IPNetwork, ...],
) -> str | None:
    """
    Walk X-Forwarded-For from right to left across the trusted-proxy boundary.
    Returns None if the header has no non-empty entries at all so the caller
    can fall back to X-Real-IP or the peer IP.
    """
    parts = [part.strip() for part in xff_header.split(",")]
    if all(not part for part in parts):
        return None

    leftmost_valid: str | None = None
    for raw_hop in reversed(parts):
        if not raw_hop:
            # Empty segment inside a non-empty chain: stop and fall back safely.
            return fallback_peer
        try:
            hop_ip = ipaddress.ip_address(raw_hop)
        except ValueError:
            # Malformed IP in chain: stop and do not trust anything further left.
            return fallback_peer

        normalized = str(hop_ip)
        leftmost_valid = normalized
        if not _is_ip_in_networks(hop_ip, networks):
            # First untrusted IP from the right is the trust boundary (client IP).
            return normalized

    # Every hop in X-Forwarded-For was a valid trusted proxy IP.
    return leftmost_valid or fallback_peer


def resolve_client_ip(
    request: Request,
    trusted_proxies: Iterable[str] | None = None,
) -> str | None:
    """
    Safely resolve the client IP address from an incoming FastAPI/Starlette Request.

    - Returns `None` if `request.client.host` is missing/empty.
    - Ignores `X-Forwarded-For` and `X-Real-IP` when the immediate peer is not
      an explicitly configured trusted proxy.
    - Validates all forwarded IP addresses with `ipaddress`.
    """
    raw_peer = request.client.host.strip() if request.client and request.client.host else ""
    if not raw_peer:
        return None

    networks, literals = _get_compiled_proxies(trusted_proxies)
    peer_normalized = _normalize_peer(raw_peer)

    if not _is_trusted_peer(raw_peer, networks, literals):
        return peer_normalized

    headers = request.headers
    xff = headers.get("x-forwarded-for")
    if xff and xff.strip():
        parsed_xff = _parse_x_forwarded_for(xff, peer_normalized, networks)
        if parsed_xff is not None:
            return parsed_xff

    x_real_ip = headers.get("x-real-ip")
    if x_real_ip and x_real_ip.strip():
        try:
            return str(ipaddress.ip_address(x_real_ip.strip()))
        except ValueError:
            return peer_normalized

    return peer_normalized


def get_client_ip(request: Request) -> str:
    """
    Non-nullable client IP key function for rate limiting (slowapi).
    Delegates to `resolve_client_ip` so rate limiting, session metadata,
    and audit logs share one trust-boundary implementation.
    """
    return resolve_client_ip(request) or "127.0.0.1"
