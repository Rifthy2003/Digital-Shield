"""
Microsoft Personal Account OAuth 2.0 / OpenID Connect service (P1-C).

Security design:
- Targets personal Microsoft accounts via the `/consumers` authority
  (`https://login.microsoftonline.com/consumers`).
- Authorization Code Flow with mandatory PKCE (S256 only), unpredictable `state`,
  and OIDC `nonce`.
- Requests minimum scopes for identity: `openid profile email User.Read`.
- Never requests mail, contacts, files, or calendar permissions.
- Redirect URI is always taken from server `Settings.MICROSOFT_REDIRECT_URI`.
- Validates Microsoft `id_token` RS256 signature against Microsoft's `/consumers`
  JWKS endpoint with bounded caching and automatic `kid`-miss refresh, plus
  strict issuer (`9188040d-6c67-4c5b-b112-36a304b66dad`), audience, nonce, and
  expiry checks.
- Fetches basic profile from Microsoft Graph `/v1.0/me` where available.
- Encrypts access and refresh tokens with `TokenCipher` and preserves
  refresh-token rotation behavior.
"""
from __future__ import annotations

import hmac
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable
from urllib.parse import urlencode

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from app.config import Settings, get_settings
from app.core.crypto import TokenCipher, get_token_cipher
from app.services.oauth_google import (
    AuthorizationRequestArtifacts,
    EncryptedOAuthTokens,
    generate_pkce_pair,
    hash_oauth_value,
)

logger = logging.getLogger(__name__)

MICROSOFT_CONSUMERS_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad"
MICROSOFT_ALLOWED_AUTHORITIES = frozenset({
    "https://login.microsoftonline.com/common",
    "https://login.microsoftonline.com/consumers",
})
MICROSOFT_DEFAULT_AUTHORITY = "https://login.microsoftonline.com/consumers"
MICROSOFT_AUTH_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
MICROSOFT_TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
MICROSOFT_JWKS_URL = "https://login.microsoftonline.com/consumers/discovery/v2.0/keys"
MICROSOFT_GRAPH_ME_URL = "https://graph.microsoft.com/v1.0/me"
MICROSOFT_CONSUMERS_ISSUERS = frozenset({
    f"https://login.microsoftonline.com/{MICROSOFT_CONSUMERS_TENANT_ID}/v2.0",
})
MICROSOFT_TRUSTED_ISSUER_PREFIX = "https://login.microsoftonline.com/"
MICROSOFT_PERSONAL_SCOPES = ("openid", "profile", "email", "User.Read")

DEFAULT_HTTP_TIMEOUT = 10.0
JWKS_CACHE_TTL_SECONDS = 3600


class MicrosoftOAuthError(Exception):
    """Base sanitized exception for Microsoft OAuth / OIDC operations."""


class MicrosoftOAuthNotConfiguredError(MicrosoftOAuthError):
    """Raised when Microsoft OAuth settings or token encryption key are missing."""


class MicrosoftOAuthProviderError(MicrosoftOAuthError):
    """Raised when Microsoft's OAuth or Graph endpoints fail or return invalid data."""


class MicrosoftIdTokenValidationError(MicrosoftOAuthError):
    """Raised when a Microsoft OIDC id_token fails signature or claims validation."""


class MicrosoftTokenRefreshError(MicrosoftOAuthProviderError):
    """Raised when refreshing a Microsoft access token fails."""


@dataclass(frozen=True)
class MicrosoftIdentity:
    provider_user_id: str
    email: str | None
    email_verified: bool
    display_name: str | None
    avatar_url: str | None = None


@dataclass(frozen=True)
class MicrosoftCallbackResult:
    identity: MicrosoftIdentity
    tokens: EncryptedOAuthTokens


class _MicrosoftJwksCache:
    """In-memory cache of Microsoft's RSA public keys with TTL and key-rotation refresh."""

    def __init__(self, jwks_url: str = MICROSOFT_JWKS_URL, ttl_seconds: int = JWKS_CACHE_TTL_SECONDS) -> None:
        self._jwks_url = jwks_url
        self._ttl_seconds = ttl_seconds
        self._keys_by_kid: dict[str, Any] = {}
        self._expires_at: float = 0.0

    def clear(self) -> None:
        self._keys_by_kid.clear()
        self._expires_at = 0.0

    async def get_signing_key(
        self,
        kid: str,
        *,
        http_client: httpx.AsyncClient | None = None,
        force_refresh: bool = False,
    ) -> Any:
        now = time.monotonic()
        if not force_refresh and now < self._expires_at and kid in self._keys_by_kid:
            return self._keys_by_kid[kid]

        await self._refresh(http_client=http_client)
        if kid in self._keys_by_kid:
            return self._keys_by_kid[kid]
        raise MicrosoftIdTokenValidationError("Unknown Microsoft signing key identifier")

    async def _refresh(self, *, http_client: httpx.AsyncClient | None = None) -> None:
        owns_client = http_client is None
        client = http_client or httpx.AsyncClient(timeout=DEFAULT_HTTP_TIMEOUT)
        try:
            resp = await client.get(self._jwks_url)
            resp.raise_for_status()
            payload = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise MicrosoftIdTokenValidationError("Unable to fetch Microsoft signing keys") from exc
        finally:
            if owns_client:
                await client.aclose()

        keys = payload.get("keys")
        if not isinstance(keys, list) or not keys:
            raise MicrosoftIdTokenValidationError("Microsoft JWKS response did not contain signing keys")

        parsed: dict[str, Any] = {}
        for jwk_dict in keys:
            if not isinstance(jwk_dict, dict):
                continue
            key_id = jwk_dict.get("kid")
            kty = jwk_dict.get("kty")
            if isinstance(key_id, str) and key_id and kty == "RSA":
                try:
                    parsed[key_id] = RSAAlgorithm.from_jwk(jwk_dict)
                except Exception:
                    continue

        if not parsed:
            raise MicrosoftIdTokenValidationError("No usable RSA signing keys found in Microsoft JWKS")

        self._keys_by_kid = parsed
        self._expires_at = time.monotonic() + self._ttl_seconds


class MicrosoftOAuthService:
    """Service encapsulating Microsoft Personal Account OAuth 2.0 + OIDC operations."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        cipher: TokenCipher | None = None,
        jwks_cache: _MicrosoftJwksCache | None = None,
        http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._cipher = cipher
        self._authority = self._resolve_authority()
        self._auth_url = f"{self._authority}/oauth2/v2.0/authorize"
        self._token_url = f"{self._authority}/oauth2/v2.0/token"
        self._jwks_url = f"{self._authority}/discovery/v2.0/keys"
        self._jwks_cache = jwks_cache or _MicrosoftJwksCache(jwks_url=self._jwks_url)
        self._http_client_factory = http_client_factory or (
            lambda: httpx.AsyncClient(timeout=DEFAULT_HTTP_TIMEOUT)
        )

    def _resolve_authority(self) -> str:
        raw = (self._settings.MICROSOFT_AUTHORITY or MICROSOFT_DEFAULT_AUTHORITY).strip().rstrip("/")
        if raw not in MICROSOFT_ALLOWED_AUTHORITIES:
            raise MicrosoftOAuthNotConfiguredError("Invalid Microsoft OAuth authority configuration")
        return raw

    def _get_cipher(self) -> TokenCipher:
        if self._cipher is not None:
            return self._cipher
        try:
            return get_token_cipher()
        except Exception as exc:
            raise MicrosoftOAuthNotConfiguredError("Token encryption key is not configured") from exc

    def _resolve_platform_config(self, platform: str = "web") -> tuple[str, str | None, str]:
        normalized = (platform or "web").strip().lower()
        if normalized == "web":
            client_id = (self._settings.MICROSOFT_CLIENT_ID or "").strip()
            client_secret = (self._settings.MICROSOFT_CLIENT_SECRET or "").strip()
            redirect_uri = (self._settings.MICROSOFT_REDIRECT_URI or "").strip()
            if not (client_id and client_secret and redirect_uri):
                raise MicrosoftOAuthNotConfiguredError("Microsoft web OAuth is not configured")
            return client_id, client_secret, redirect_uri

        if normalized in ("android", "ios"):
            client_id = (
                (self._settings.MICROSOFT_MOBILE_CLIENT_ID or "").strip()
                or (self._settings.MICROSOFT_CLIENT_ID or "").strip()
            )
            raw_uri = (
                self._settings.MICROSOFT_ANDROID_REDIRECT_URI
                if normalized == "android"
                else self._settings.MICROSOFT_IOS_REDIRECT_URI
            )
            redirect_uri = (raw_uri or "").strip()
            if not (client_id and redirect_uri):
                raise MicrosoftOAuthNotConfiguredError(
                    f"Microsoft {normalized} OAuth is not configured"
                )
            # Public mobile clients NEVER use a client_secret.
            return client_id, None, redirect_uri

        raise MicrosoftOAuthProviderError("Unsupported OAuth platform")

    def _require_config(self) -> tuple[str, str, str]:
        client_id, client_secret, redirect_uri = self._resolve_platform_config("web")
        assert client_secret is not None
        return client_id, client_secret, redirect_uri

    def build_authorization_request(
        self,
        *,
        platform: str = "web",
        raw_state: str | None = None,
        raw_nonce: str | None = None,
    ) -> AuthorizationRequestArtifacts:
        client_id, _, redirect_uri = self._resolve_platform_config(platform)
        cipher = self._get_cipher()

        state = raw_state or secrets.token_urlsafe(32)
        nonce = raw_nonce or secrets.token_urlsafe(32)
        code_verifier, code_challenge = generate_pkce_pair()

        scopes_str = " ".join(MICROSOFT_PERSONAL_SCOPES)
        query = urlencode({
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "response_mode": "query",
            "scope": scopes_str,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "nonce": nonce,
            "prompt": "select_account",
        })

        return AuthorizationRequestArtifacts(
            authorization_url=f"{self._auth_url}?{query}",
            state_hash=hash_oauth_value(state),
            nonce_hash=hash_oauth_value(nonce),
            code_verifier_encrypted=cipher.encrypt(code_verifier),
            redirect_uri=redirect_uri,
            scopes=scopes_str,
        )

    async def validate_id_token(
        self,
        id_token: str,
        *,
        expected_nonce_hash: str,
        expected_audience: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> dict[str, Any]:
        audience = expected_audience or (
            (self._settings.MICROSOFT_CLIENT_ID or "").strip()
            or (self._settings.MICROSOFT_MOBILE_CLIENT_ID or "").strip()
        )
        if not audience:
            raise MicrosoftOAuthNotConfiguredError("Microsoft OAuth is not configured")
        if not id_token or not expected_nonce_hash:
            raise MicrosoftIdTokenValidationError("Missing id_token or expected nonce")

        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise MicrosoftIdTokenValidationError("Malformed id_token header") from exc

        alg = header.get("alg")
        kid = header.get("kid")
        if alg != "RS256" or not isinstance(kid, str) or not kid:
            raise MicrosoftIdTokenValidationError("Unsupported id_token signing algorithm or missing kid")

        owns_client = http_client is None
        client = http_client or self._http_client_factory()
        try:
            signing_key = await self._jwks_cache.get_signing_key(kid, http_client=client)
            try:
                claims = jwt.decode(
                    id_token,
                    key=signing_key,
                    algorithms=["RS256"],
                    audience=audience,
                    options={
                        "require": ["iss", "sub", "aud", "exp", "iat"],
                        "verify_signature": True,
                        "verify_exp": True,
                        "verify_iat": True,
                        "verify_aud": True,
                        "verify_iss": False,
                    },
                    leeway=30,
                )
            except jwt.InvalidSignatureError:
                signing_key = await self._jwks_cache.get_signing_key(
                    kid, http_client=client, force_refresh=True
                )
                try:
                    claims = jwt.decode(
                        id_token,
                        key=signing_key,
                        algorithms=["RS256"],
                        audience=audience,
                        options={
                            "require": ["iss", "sub", "aud", "exp", "iat"],
                            "verify_signature": True,
                            "verify_exp": True,
                            "verify_iat": True,
                            "verify_aud": True,
                            "verify_iss": False,
                        },
                        leeway=30,
                    )
                except jwt.PyJWTError as exc:
                    raise MicrosoftIdTokenValidationError("Invalid id_token signature or claims") from exc
            except jwt.PyJWTError as exc:
                raise MicrosoftIdTokenValidationError("Invalid id_token claims") from exc
        finally:
            if owns_client:
                await client.aclose()

        issuer = claims.get("iss")
        tid = claims.get("tid")
        if not isinstance(issuer, str) or not isinstance(tid, str):
            raise MicrosoftIdTokenValidationError("Missing id_token issuer or tenant id")

        normalized_tid = tid.strip().lower()
        try:
            parsed_tid = uuid.UUID(normalized_tid)
        except ValueError as exc:
            raise MicrosoftIdTokenValidationError("Invalid id_token tenant id") from exc
        if str(parsed_tid) != normalized_tid:
            raise MicrosoftIdTokenValidationError("Malformed id_token tenant id")

        if self._authority.endswith("/consumers") and normalized_tid != MICROSOFT_CONSUMERS_TENANT_ID:
            raise MicrosoftIdTokenValidationError(
                "Organizational tenant token is not permitted for /consumers authority"
            )

        expected_issuer = f"{MICROSOFT_TRUSTED_ISSUER_PREFIX}{normalized_tid}/v2.0"
        if not hmac.compare_digest(issuer, expected_issuer):
            raise MicrosoftIdTokenValidationError("Untrusted or mismatched id_token issuer")

        raw_nonce = claims.get("nonce")
        if not isinstance(raw_nonce, str) or not raw_nonce:
            raise MicrosoftIdTokenValidationError("Missing id_token nonce")
        if not hmac.compare_digest(hash_oauth_value(raw_nonce), expected_nonce_hash):
            raise MicrosoftIdTokenValidationError("id_token nonce mismatch")

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise MicrosoftIdTokenValidationError("Missing id_token subject")

        return claims

    async def fetch_graph_profile(
        self,
        access_token: str,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> dict[str, Any]:
        """Fetch basic profile (`id`, `displayName`, `mail`, `userPrincipalName`) from Graph `/me`."""
        if not access_token:
            return {}
        owns_client = http_client is None
        client = http_client or self._http_client_factory()
        try:
            resp = await client.get(
                MICROSOFT_GRAPH_ME_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if resp.status_code != 200:
                logger.warning("Microsoft Graph /me returned status %s", resp.status_code)
                return {}
            data = resp.json()
            return data if isinstance(data, dict) else {}
        except (httpx.HTTPError, ValueError):
            logger.warning("Microsoft Graph /me request failed")
            return {}
        finally:
            if owns_client:
                await client.aclose()

    def _encrypt_token_payload(
        self,
        token_payload: dict[str, Any],
        *,
        existing_refresh_token_encrypted: str | None = None,
    ) -> EncryptedOAuthTokens:
        cipher = self._get_cipher()
        access_token = token_payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise MicrosoftOAuthProviderError("Microsoft token response missing access_token")

        refresh_token = token_payload.get("refresh_token")
        if isinstance(refresh_token, str) and refresh_token:
            refresh_encrypted = cipher.encrypt(refresh_token)
        else:
            refresh_encrypted = existing_refresh_token_encrypted

        expires_in = token_payload.get("expires_in")
        expires_at: datetime | None = None
        if isinstance(expires_in, (int, float)) and expires_in > 0:
            expires_at = datetime.utcnow() + timedelta(seconds=int(expires_in))

        token_type = token_payload.get("token_type")
        if not isinstance(token_type, str) or not token_type:
            token_type = "Bearer"

        scope_str = token_payload.get("scope")
        if not isinstance(scope_str, str) or not scope_str.strip():
            scope_str = " ".join(MICROSOFT_PERSONAL_SCOPES)

        return EncryptedOAuthTokens(
            access_token_encrypted=cipher.encrypt(access_token),
            refresh_token_encrypted=refresh_encrypted,
            encryption_key_id=cipher.key_id,
            token_type=token_type,
            expires_at=expires_at,
            scopes=scope_str.strip(),
        )

    async def exchange_code_for_tokens(
        self,
        *,
        code: str,
        code_verifier_encrypted: str,
        expected_nonce_hash: str,
        platform: str = "web",
        expected_redirect_uri: str | None = None,
        existing_refresh_token_encrypted: str | None = None,
    ) -> MicrosoftCallbackResult:
        client_id, client_secret, redirect_uri = self._resolve_platform_config(platform)
        if expected_redirect_uri is not None and not hmac.compare_digest(
            expected_redirect_uri.strip(), redirect_uri
        ):
            raise MicrosoftOAuthProviderError("Redirect URI mismatch")
        cipher = self._get_cipher()

        if not code or not code.strip():
            raise MicrosoftOAuthProviderError("Missing authorization code")

        code_verifier = cipher.decrypt(code_verifier_encrypted)

        token_data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code.strip(),
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "scope": " ".join(MICROSOFT_PERSONAL_SCOPES),
        }
        if client_secret is not None:
            token_data["client_secret"] = client_secret

        async with self._http_client_factory() as client:
            try:
                token_resp = await client.post(
                    self._token_url,
                    data=token_data,
                    headers={"Accept": "application/json"},
                )
            except httpx.HTTPError as exc:
                raise MicrosoftOAuthProviderError("Microsoft token exchange request failed") from exc

            if token_resp.status_code != 200:
                logger.warning("Microsoft token exchange failed with status %s", token_resp.status_code)
                raise MicrosoftOAuthProviderError("Microsoft token exchange failed")

            try:
                token_payload = token_resp.json()
            except ValueError as exc:
                raise MicrosoftOAuthProviderError("Microsoft token endpoint returned invalid JSON") from exc

            id_token = token_payload.get("id_token")
            if not isinstance(id_token, str) or not id_token:
                raise MicrosoftIdTokenValidationError("Microsoft token response missing id_token")

            claims = await self.validate_id_token(
                id_token,
                expected_nonce_hash=expected_nonce_hash,
                expected_audience=client_id,
                http_client=client,
            )

            access_token = token_payload.get("access_token", "")
            profile = await self.fetch_graph_profile(access_token, http_client=client)

        encrypted_tokens = self._encrypt_token_payload(
            token_payload,
            existing_refresh_token_encrypted=existing_refresh_token_encrypted,
        )

        # Prefer stable OIDC subject (`sub`), or `oid` if present
        provider_user_id = str(claims.get("oid") or claims["sub"]).strip()
        email = (
            claims.get("email")
            or claims.get("preferred_username")
            or profile.get("mail")
            or profile.get("userPrincipalName")
        )
        display_name = profile.get("displayName") or claims.get("name")
        email_verified = bool(claims.get("email") or profile.get("mail"))

        identity = MicrosoftIdentity(
            provider_user_id=provider_user_id,
            email=email if isinstance(email, str) else None,
            email_verified=email_verified,
            display_name=display_name if isinstance(display_name, str) else None,
        )
        return MicrosoftCallbackResult(identity=identity, tokens=encrypted_tokens)

    async def refresh_access_token(
        self,
        encrypted_refresh_token: str,
        *,
        platform: str = "web",
    ) -> EncryptedOAuthTokens:
        client_id, client_secret, _ = self._resolve_platform_config(platform)
        cipher = self._get_cipher()
        refresh_token = cipher.decrypt(encrypted_refresh_token)

        refresh_data: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "scope": " ".join(MICROSOFT_PERSONAL_SCOPES),
        }
        if client_secret is not None:
            refresh_data["client_secret"] = client_secret

        async with self._http_client_factory() as client:
            try:
                resp = await client.post(
                    self._token_url,
                    data=refresh_data,
                    headers={"Accept": "application/json"},
                )
            except httpx.HTTPError as exc:
                raise MicrosoftTokenRefreshError("Microsoft token refresh request failed") from exc

            if resp.status_code != 200:
                logger.warning("Microsoft token refresh failed with status %s", resp.status_code)
                raise MicrosoftTokenRefreshError("Microsoft token refresh failed")

            try:
                token_payload = resp.json()
            except ValueError as exc:
                raise MicrosoftTokenRefreshError("Microsoft refresh endpoint returned invalid JSON") from exc

        return self._encrypt_token_payload(
            token_payload,
            existing_refresh_token_encrypted=encrypted_refresh_token,
        )
