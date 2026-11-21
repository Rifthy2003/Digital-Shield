"""
Breach monitoring provider interface.

Per the development rules: if no provider API key is configured, this
module returns an explicit "not configured" result. It never fabricates
breach data. Swap `HibpBreachProvider` for another implementation of
`BreachProvider` to change providers without touching calling code.
"""
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import httpx

from app.config import get_settings

HIBP_BREACH_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"


@dataclass
class BreachResult:
    configured: bool
    exposure_found: bool = False
    breach_count: int = 0
    breach_names: list[str] = field(default_factory=list)
    message: str = ""


class BreachProvider(ABC):
    @abstractmethod
    async def check_email(self, email: str) -> BreachResult: ...


class UnconfiguredBreachProvider(BreachProvider):
    async def check_email(self, email: str) -> BreachResult:
        return BreachResult(
            configured=False,
            message=(
                "Live breach checking is not configured for this deployment "
                "(no HIBP_API_KEY set). No breach data is available — this is "
                "not the same as 'no breaches found'."
            ),
        )


class HibpBreachProvider(BreachProvider):
    def __init__(self, api_key: str):
        self._api_key = api_key

    async def check_email(self, email: str) -> BreachResult:
        headers = {"hibp-api-key": self._api_key, "user-agent": "InforaDigitalShield"}
        url = HIBP_BREACH_API.format(account=email)
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers, params={"truncateResponse": "true"})
            if resp.status_code == 404:
                return BreachResult(configured=True, exposure_found=False, message="No known breaches found.")
            resp.raise_for_status()
            breaches = resp.json()
            names = [b.get("Name", "unknown") for b in breaches]
            return BreachResult(
                configured=True,
                exposure_found=True,
                breach_count=len(names),
                breach_names=names,
                message=f"Found in {len(names)} known breach(es).",
            )


def get_breach_provider() -> BreachProvider:
    settings = get_settings()
    if settings.HIBP_API_KEY:
        return HibpBreachProvider(settings.HIBP_API_KEY)
    return UnconfiguredBreachProvider()


def sha1_upper(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest().upper()
