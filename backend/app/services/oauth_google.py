"""
Google OAuth 2.0 / OpenID Connect provider service (Phase 18 — Task 18.4).

Security design:
- Authorization Code Flow with mandatory PKCE (S256 only), unpredictable `state`,
  and OIDC `nonce`.
- Only SHA-256 hashes of `state` and `nonce` and Fernet-encrypted PKCE
  `code_verifier` are returned for persistence in `OAuthState`.
- Redirect URI is always taken from server `Settings.GOOGLE_REDIRECT_URI`
  (never trusted from client/frontend input).
- Requests minimum initial scopes: `openid email profile`.
- Verifies Google `id_token` RS256 signature against Google's JWKS endpoint
  (`https://www.googleapis.com/oauth2/v3/certs`) with bounded caching and
  automatic refresh on key rotation (`kid` miss).
- Encrypts provider tokens with `TokenCipher` before returning to callers,
  preserving any existing encrypted refresh token when Google omits a new one.
- Never logs or includes tokens, authorization codes, verifiers, or client
  secrets in exception messages.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable
from urllib.parse import urlencode

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from app.config import Settings, get_settings
from app.core.crypto import TokenCipher, get_token_cipher

logger = logging.getLogger(__name__)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = frozenset({"https://accounts.google.com", "accounts.google.com"})
GOOGLE_INITIAL_SCOPES = ("openid", "email", "profile")

DEFAULT_HTTP_TIMEOUT = 10.0
JWKS_CACHE_TTL_SECONDS = 3600


class GoogleOAuthError(Exception):
    """Base sanitized exception for Google OAuth / OIDC operations."""


class GoogleOAuthNotConfiguredError(GoogleOAuthError):
    """Raised when Google OAuth settings or token encryption key are missing."""


class GoogleOAuthProviderError(GoogleOAuthError):
    """Raised when Google's OAuth endpoints fail, time out, or return invalid data."""


class GoogleIdTokenValidationError(GoogleOAuthError):
    """Raised when a Google OIDC id_token fails signature or claims validation."""


class GoogleTokenRefreshError(GoogleOAuthProviderError):
    """Raised when refreshing a Google access token fails (e.g. invalid_grant)."""


class GoogleTokenRevocationError(GoogleOAuthProviderError):
    """Raised when Google reports a failure or network error during revocation."""


@dataclass(frozen=True)
class AuthorizationRequestArtifacts:
    authorization_url: str
    state_hash: str
    nonce_hash: str
    code_verifier_encrypted: str
    redirect_uri: str
    scopes: str


@dataclass(frozen=True)
class GoogleIdentity:
    provider_user_id: str
    email: str | None
    email_verified: bool
    display_name: str | None
    avatar_url: str | None


@dataclass(frozen=True)
class EncryptedOAuthTokens:
    access_token_encrypted: str
    refresh_token_encrypted: str | None
    encryption_key_id: str
    token_type: str
    expires_at: datetime | None
    scopes: str


@dataclass(frozen=True)
class GoogleCallbackResult:
    identity: GoogleIdentity
    tokens: EncryptedOAuthTokens


def hash_oauth_value(raw_value: str) -> str:
    """Return SHA-256 hex digest of an OAuth state or nonce."""
    return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()


def generate_pkce_pair() -> tuple[str, str]:
    """
    Generate a cryptographically random PKCE `(code_verifier, code_challenge)`
    using `S256` (RFC 7636). Plain PKCE is never used.
    """
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def verify_pkce_challenge(code_verifier: str, expected_challenge: str) -> bool:
    """Verify a PKCE `code_verifier` against an `S256` challenge."""
    if not code_verifier or not expected_challenge:
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(computed, expected_challenge)


class _GoogleJwksCache:
    """In-memory cache of Google's RSA public keys with TTL and key-rotation refresh."""

    def __init__(self, jwks_url: str = GOOGLE_JWKS_URL, ttl_seconds: int = JWKS_CACHE_TTL_SECONDS) -> None:
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
        client: httpx.AsyncClient,
    ) -> Any:
        now = time.monotonic()
        if now < self._expires_at and kid in self._keys_by_kid:
            return self._keys_by_kid[kid]

        # Fetch fresh JWKS (either cache expired or `kid` rotated)
        await self._refresh(client)
        if kid not in self._keys_by_kid:
            raise GoogleIdTokenValidationError("Google ID token signing key not found in JWKS.")
        return self._keys_by_kid[kid]

    async def _refresh(self, client: httpx.AsyncClient) -> None:
        try:
            resp = await client.get(self._jwks_url)
            resp.raise_for_status()
            payload = resp.json()
        except (httpx.TimeoutException, httpx.RequestError, httpx.HTTPStatusError, ValueError) as exc:
            logger.warning("Failed to fetch Google JWKS: %s", type(exc).__name__)
            raise GoogleIdTokenValidationError("Unable to retrieve Google signing keys.") from exc

        raw_keys = payload.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise GoogleIdTokenValidationError("Google JWKS response contained no keys.")

        parsed: dict[str, Any] = {}
        for jwk_dict in raw_keys:
            if not isinstance(jwk_dict, dict):
                continue
            kid = jwk_dict.get("kid")
            if not kid or jwk_dict.get("kty") != "RSA":
                continue
            try:
                parsed[str(kid)] = RSAAlgorithm.from_jwk(jwk_dict)
            except Exception:
                continue

        if not parsed:
            raise GoogleIdTokenValidationError("Google JWKS response contained no usable RSA keys.")

        self._keys_by_kid = parsed
        self._expires_at = time.monotonic() + self._ttl_seconds


class GoogleOAuthService:
    """Google OAuth 2.0 / OIDC service for account linking, refresh, and revocation."""

    def __init__(
        self,
        settings: Settings | None = None,
        cipher: TokenCipher | None = None,
        http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
        jwks_cache: _GoogleJwksCache | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._cipher = cipher
        self._http_client_factory = http_client_factory
        self._jwks_cache = jwks_cache or _GoogleJwksCache()

    def _require_configured(self) -> tuple[str, str, str, TokenCipher]:
        s = self._settings
        if not (s.GOOGLE_CLIENT_ID and s.GOOGLE_CLIENT_SECRET and s.GOOGLE_REDIRECT_URI):
            raise GoogleOAuthNotConfiguredError("Google OAuth is not configured.")
        cipher = self._cipher or get_token_cipher()
        return (
            s.GOOGLE_CLIENT_ID.strip(),
            s.GOOGLE_CLIENT_SECRET.strip(),
            s.GOOGLE_REDIRECT_URI.strip(),
            cipher,
        )

    def _new_http_client(self) -> httpx.AsyncClient:
        if self._http_client_factory is not None:
            return self._http_client_factory()
        return httpx.AsyncClient(timeout=DEFAULT_HTTP_TIMEOUT)

    def build_authorization_request(self) -> AuthorizationRequestArtifacts:
        """
        Build a Google OIDC Authorization Code URL with PKCE (S256), state, and nonce.
        Only hashed state/nonce and encrypted PKCE verifier are returned for storage.
        """
        client_id, _, redirect_uri, cipher = self._require_configured()

        raw_state = secrets.token_urlsafe(32)
        raw_nonce = secrets.token_urlsafe(32)
        code_verifier, code_challenge = generate_pkce_pair()
        scopes = " ".join(GOOGLE_INITIAL_SCOPES)

        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scopes,
            "state": raw_state,
            "nonce": raw_nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "prompt": "consent",
            "include_granted_scopes": "false",
        }
        authorization_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"

        return AuthorizationRequestArtifacts(
            authorization_url=authorization_url,
            state_hash=hash_oauth_value(raw_state),
            nonce_hash=hash_oauth_value(raw_nonce),
            code_verifier_encrypted=cipher.encrypt(code_verifier),
            redirect_uri=redirect_uri,
            scopes=scopes,
        )

    async def verify_id_token(
        self,
        id_token: str,
        expected_nonce_hash: str,
    ) -> GoogleIdentity:
        """
        Verify a Google OIDC `id_token` (RS256 signature via Google JWKS,
        `iss`, `aud`, `exp`, `iat`, `sub`, and `nonce` hash) and extract identity.
        """
        client_id, _, _, _ = self._require_configured()

        if not id_token or not isinstance(id_token, str):
            raise GoogleIdTokenValidationError("Missing Google ID token.")
        if not expected_nonce_hash:
            raise GoogleIdTokenValidationError("Missing expected OIDC nonce hash.")

        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise GoogleIdTokenValidationError("Malformed Google ID token header.") from exc

        if header.get("alg") != "RS256" or not header.get("kid"):
            raise GoogleIdTokenValidationError("Unsupported Google ID token algorithm or missing key ID.")

        async with self._new_http_client() as client:
            signing_key = await self._jwks_cache.get_signing_key(str(header["kid"]), client)

        try:
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key=signing_key,
                algorithms=["RS256"],
                audience=client_id,
                leeway=30,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise GoogleIdTokenValidationError("Google ID token has expired.") from exc
        except jwt.InvalidAudienceError as exc:
            raise GoogleIdTokenValidationError("Google ID token audience mismatch.") from exc
        except jwt.PyJWTError as exc:
            raise GoogleIdTokenValidationError("Google ID token signature or claims validation failed.") from exc

        issuer = claims.get("iss")
        if issuer not in GOOGLE_ISSUERS:
            raise GoogleIdTokenValidationError("Google ID token issuer mismatch.")

        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub.strip():
            raise GoogleIdTokenValidationError("Google ID token missing subject claim.")

        raw_nonce = claims.get("nonce")
        if not isinstance(raw_nonce, str) or not raw_nonce:
            raise GoogleIdTokenValidationError("Google ID token missing nonce claim.")
        if not hmac.compare_digest(hash_oauth_value(raw_nonce), expected_nonce_hash):
            raise GoogleIdTokenValidationError("Google ID token nonce mismatch.")

        email = claims.get("email")
        display_name = claims.get("name")
        avatar_url = claims.get("picture")

        return GoogleIdentity(
            provider_user_id=sub.strip(),
            email=email.strip() if isinstance(email, str) and email.strip() else None,
            email_verified=bool(claims.get("email_verified", False)),
            display_name=display_name.strip() if isinstance(display_name, str) and display_name.strip() else None,
            avatar_url=avatar_url.strip() if isinstance(avatar_url, str) and avatar_url.strip() else None,
        )

    async def exchange_code_for_tokens(
        self,
        code: str,
        code_verifier_encrypted: str,
        expected_nonce_hash: str,
        existing_refresh_token_encrypted: str | None = None,
    ) -> GoogleCallbackResult:
        """
        Exchange an authorization code + decrypted PKCE verifier with Google,
        verify the returned `id_token`, and return encrypted tokens + identity.
        Preserves `existing_refresh_token_encrypted` if Google omits `refresh_token`.
        """
        client_id, client_secret, redirect_uri, cipher = self._require_configured()

        if not code or not code.strip():
            raise GoogleOAuthProviderError("Missing authorization code.")
        if not expected_nonce_hash:
            raise GoogleIdTokenValidationError("Missing expected OIDC nonce hash.")

        code_verifier = cipher.decrypt(code_verifier_encrypted)

        form_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code.strip(),
            "code_verifier": code_verifier,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }

        payload = await self._post_form(
            GOOGLE_TOKEN_URL,
            form_data,
            error_cls=GoogleOAuthProviderError,
            operation="token_exchange",
        )

        access_token = payload.get("access_token")
        id_token = payload.get("id_token")
        if not isinstance(access_token, str) or not access_token:
            raise GoogleOAuthProviderError("Google token response missing access_token.")
        if not isinstance(id_token, str) or not id_token:
            raise GoogleOAuthProviderError("Google token response missing id_token.")

        identity = await self.verify_id_token(id_token, expected_nonce_hash=expected_nonce_hash)

        raw_refresh = payload.get("refresh_token")
        if isinstance(raw_refresh, str) and raw_refresh.strip():
            refresh_encrypted = cipher.encrypt(raw_refresh.strip())
        else:
            refresh_encrypted = existing_refresh_token_encrypted

        expires_at = _compute_expires_at(payload.get("expires_in"))
        token_type = str(payload.get("token_type") or "Bearer")
        granted_scopes = str(payload.get("scope") or " ".join(GOOGLE_INITIAL_SCOPES))

        return GoogleCallbackResult(
            identity=identity,
            tokens=EncryptedOAuthTokens(
                access_token_encrypted=cipher.encrypt(access_token),
                refresh_token_encrypted=refresh_encrypted,
                encryption_key_id=cipher.key_id,
                token_type=token_type,
                expires_at=expires_at,
                scopes=granted_scopes,
            ),
        )

    async def refresh_access_token(self, refresh_token_encrypted: str) -> EncryptedOAuthTokens:
        """
        Refresh a Google access token using an encrypted refresh token.
        Preserves the existing refresh token if Google omits a replacement.
        """
        client_id, client_secret, _, cipher = self._require_configured()
        raw_refresh = cipher.decrypt(refresh_token_encrypted)

        form_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": raw_refresh,
            "grant_type": "refresh_token",
        }

        payload = await self._post_form(
            GOOGLE_TOKEN_URL,
            form_data,
            error_cls=GoogleTokenRefreshError,
            operation="token_refresh",
        )

        new_access = payload.get("access_token")
        if not isinstance(new_access, str) or not new_access:
            raise GoogleTokenRefreshError("Google refresh response missing access_token.")

        new_refresh = payload.get("refresh_token")
        if isinstance(new_refresh, str) and new_refresh.strip():
            next_refresh_encrypted = cipher.encrypt(new_refresh.strip())
        else:
            next_refresh_encrypted = cipher.rotate(refresh_token_encrypted)

        return EncryptedOAuthTokens(
            access_token_encrypted=cipher.encrypt(new_access),
            refresh_token_encrypted=next_refresh_encrypted,
            encryption_key_id=cipher.key_id,
            token_type=str(payload.get("token_type") or "Bearer"),
            expires_at=_compute_expires_at(payload.get("expires_in")),
            scopes=str(payload.get("scope") or " ".join(GOOGLE_INITIAL_SCOPES)),
        )

    async def revoke_token(self, encrypted_token: str) -> None:
        """
        Revoke an encrypted Google access or refresh token via Google's revocation endpoint.
        Raises `GoogleTokenRevocationError` if Google returns a failure or network error.
        """
        _, _, _, cipher = self._require_configured()
        raw_token = cipher.decrypt(encrypted_token)

        async with self._new_http_client() as client:
            try:
                resp = await client.post(
                    GOOGLE_REVOKE_URL,
                    data={"token": raw_token},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            except (httpx.TimeoutException, httpx.RequestError) as exc:
                logger.warning("Google token revocation request failed: %s", type(exc).__name__)
                raise GoogleTokenRevocationError("Google token revocation request failed.") from exc

        if resp.status_code != 200:
            err_code = _extract_oauth_error_code(resp)
            logger.warning("Google token revocation rejected (status=%s, error=%s)", resp.status_code, err_code)
            raise GoogleTokenRevocationError(
                f"Google token revocation failed (status {resp.status_code})."
            )

    async def _post_form(
        self,
        url: str,
        form_data: dict[str, str],
        error_cls: type[GoogleOAuthProviderError],
        operation: str,
    ) -> dict[str, Any]:
        async with self._new_http_client() as client:
            try:
                resp = await client.post(
                    url,
                    data=form_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            except httpx.TimeoutException as exc:
                logger.warning("Google OAuth %s timed out", operation)
                raise error_cls(f"Google OAuth {operation} timed out.") from exc
            except httpx.RequestError as exc:
                logger.warning("Google OAuth %s network error: %s", operation, type(exc).__name__)
                raise error_cls(f"Google OAuth {operation} network error.") from exc

        if resp.status_code != 200:
            err_code = _extract_oauth_error_code(resp)
            logger.warning(
                "Google OAuth %s failed (status=%s, error=%s)",
                operation,
                resp.status_code,
                err_code,
            )
            raise error_cls(f"Google OAuth {operation} rejected by provider ({err_code}).")

        try:
            payload = resp.json()
        except ValueError as exc:
            logger.warning("Google OAuth %s returned non-JSON response", operation)
            raise error_cls(f"Google OAuth {operation} returned invalid JSON.") from exc

        if not isinstance(payload, dict):
            raise error_cls(f"Google OAuth {operation} returned unexpected payload format.")
        return payload


def _extract_oauth_error_code(resp: httpx.Response) -> str:
    try:
        data = resp.json()
        if isinstance(data, dict) and isinstance(data.get("error"), str):
            return data["error"][:64]
    except Exception:
        pass
    return f"http_{resp.status_code}"


def _compute_expires_at(expires_in: Any) -> datetime | None:
    if isinstance(expires_in, (int, float)) and expires_in > 0:
        return datetime.utcnow() + timedelta(seconds=int(expires_in))
    return None
