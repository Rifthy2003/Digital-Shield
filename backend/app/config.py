"""
Centralized application configuration.

All secrets and environment-specific values are loaded from environment
variables (see .env.example). Nothing sensitive is hardcoded here, and
nothing here should ever be committed with real values filled in.
"""
import logging
from urllib.parse import urlparse
from functools import lru_cache
from typing import List

from cryptography.fernet import Fernet
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url

logger = logging.getLogger(__name__)

INSECURE_DEV_JWT_SECRET = "CHANGE_ME_INSECURE_DEV_ONLY_DO_NOT_USE_IN_PRODUCTION"
DISALLOWED_JWT_SECRETS = {
    INSECURE_DEV_JWT_SECRET.lower(),
    "replace_with_a_long_random_value",
    "secret",
    "password",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Application ---
    APP_NAME: str = "Infora Digital Shield"
    ENVIRONMENT: str = Field(default="development")  # development | staging | production
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # --- Database ---
    POSTGRES_USER: str = "infora"
    POSTGRES_PASSWORD: str = "change_me_dev_only"
    POSTGRES_DB: str = "infora_digital_shield"
    POSTGRES_HOST: str = "db"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str = "postgresql+psycopg://infora:change_me_dev_only@db:5432/infora_digital_shield"

    @field_validator("DATABASE_URL", mode="after")
    @classmethod
    def sanitize_database_url(cls, v: str) -> str:
        """
        Safely normalize the database URL and ensure credentials with special
        characters are properly URL-encoded for SQLAlchemy and drivers.
        """
        if not v:
            return v
        try:
            url = make_url(v)
            return url.render_as_string(hide_password=False)
        except Exception:
            return v

    @model_validator(mode="after")
    def assemble_database_url(self) -> "Settings":
        if not self.DATABASE_URL:
            self.DATABASE_URL = URL.create(
                drivername="postgresql+psycopg",
                username=self.POSTGRES_USER,
                password=self.POSTGRES_PASSWORD,
                host=self.POSTGRES_HOST,
                port=self.POSTGRES_PORT,
                database=self.POSTGRES_DB,
            ).render_as_string(hide_password=False)
        return self

    # --- Auth / JWT ---
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(64))"
    JWT_SECRET_KEY: str = Field(default=INSECURE_DEV_JWT_SECRET)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # --- MFA (TOTP) ---
    MFA_ISSUER_NAME: str = "Infora Digital Shield"
    MFA_TOTP_WINDOW: int = 1  # +/- 1 step (30s) clock skew tolerance
    MFA_CHALLENGE_EXPIRE_MINUTES: int = 5
    MFA_PENDING_EXPIRE_MINUTES: int = 10
    MFA_RECOVERY_CODE_COUNT: int = 8

    @model_validator(mode="after")
    def validate_jwt_secret_key(self) -> "Settings":
        raw_secret = self.JWT_SECRET_KEY
        if not raw_secret or not raw_secret.strip():
            raise ValueError("JWT_SECRET_KEY cannot be empty or whitespace-only.")

        is_production = self.ENVIRONMENT.strip().lower() == "production"

        if is_production:
            if raw_secret == INSECURE_DEV_JWT_SECRET:
                raise ValueError(
                    "JWT_SECRET_KEY must be explicitly configured in production; default fallback is not permitted."
                )
            if raw_secret.strip().lower() in DISALLOWED_JWT_SECRETS:
                raise ValueError(
                    "JWT_SECRET_KEY is set to a known insecure placeholder; a strong random secret is required in production."
                )
            if len(raw_secret.strip()) < 32:
                raise ValueError(
                    "JWT_SECRET_KEY must be at least 32 characters long in production."
                )
        else:
            if raw_secret == INSECURE_DEV_JWT_SECRET:
                logger.warning(
                    "INSECURE CONFIGURATION: Using default development JWT secret fallback. Set JWT_SECRET_KEY in your environment for security."
                )

        return self

    # --- CORS ---
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:5174", "http://localhost:3000"]

    # --- Rate limiting ---
    RATE_LIMIT_DEFAULT: str = "60/minute"
    RATE_LIMIT_AUTH: str = "10/minute"
    RATE_LIMIT_SCAN: str = "20/minute"

    # --- Trusted Reverse Proxies (SEC-07) ---
    # Explicit list of trusted reverse-proxy IPs, CIDR ranges, or local test identifiers.
    # Forwarded headers (X-Forwarded-For, X-Real-IP) are ONLY trusted when the immediate
    # connecting peer belongs to this list. Do NOT add 0.0.0.0/0 or broad private subnets
    # unless every host in that range is a controlled reverse proxy.
    # Production example: TRUSTED_PROXIES=["10.0.1.10/32","172.18.0.0/24"]
    TRUSTED_PROXIES: List[str] = ["127.0.0.1", "::1", "localhost", "testclient"]

    @field_validator("TRUSTED_PROXIES", mode="before")
    @classmethod
    def parse_trusted_proxies(cls, v: object) -> list[str]:
        if isinstance(v, str):
            stripped = v.strip()
            if not stripped:
                return []
            if not stripped.startswith("["):
                return [item.strip() for item in stripped.split(",") if item.strip()]
        return v

    # --- Third-party providers (optional; features degrade honestly if unset) ---
    HIBP_API_KEY: str | None = None  # Have I Been Pwned — breach monitoring
    AI_PROVIDER_API_KEY: str | None = None  # AI assistant backing provider
    AI_PROVIDER_MODEL: str = "not-configured"

    # --- Data retention (days) ---
    MESSAGE_CHECK_RETENTION_DAYS: int = 30
    URL_CHECK_RETENTION_DAYS: int = 90

    # --- Encryption key for OAuth tokens at rest ---
    # Must be one or more comma-separated urlsafe base64-encoded 32-byte Fernet keys.
    # For zero-downtime rotation, prepend the new primary key: "<new_key>,<old_key>".
    TOKEN_ENCRYPTION_KEY: str | None = None

    # --- Google OAuth / OpenID Connect (Phase 18) ---
    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: str | None = None
    GOOGLE_REDIRECT_URI: str | None = None

    @property
    def google_oauth_enabled(self) -> bool:
        return bool(
            (self.GOOGLE_CLIENT_ID and self.GOOGLE_CLIENT_ID.strip())
            or (self.GOOGLE_CLIENT_SECRET and self.GOOGLE_CLIENT_SECRET.strip())
            or (self.GOOGLE_REDIRECT_URI and self.GOOGLE_REDIRECT_URI.strip())
        )

    @model_validator(mode="after")
    def validate_oauth_configuration(self) -> "Settings":
        raw_enc_key = self.TOKEN_ENCRYPTION_KEY
        if raw_enc_key is not None and raw_enc_key.strip():
            keys = [k.strip() for k in raw_enc_key.split(",") if k.strip()]
            if not keys:
                raise ValueError("TOKEN_ENCRYPTION_KEY cannot be whitespace-only.")
            for key in keys:
                try:
                    Fernet(key.encode("utf-8"))
                except Exception as exc:
                    raise ValueError(
                        "Invalid TOKEN_ENCRYPTION_KEY format; expected urlsafe base64-encoded 32-byte Fernet key(s)."
                    ) from exc

        if not self.google_oauth_enabled:
            return self

        missing = [
            name
            for name, val in (
                ("GOOGLE_CLIENT_ID", self.GOOGLE_CLIENT_ID),
                ("GOOGLE_CLIENT_SECRET", self.GOOGLE_CLIENT_SECRET),
                ("GOOGLE_REDIRECT_URI", self.GOOGLE_REDIRECT_URI),
            )
            if not val or not val.strip()
        ]
        if missing:
            raise ValueError(
                f"Incomplete Google OAuth configuration; missing required setting(s): {', '.join(missing)}."
            )

        parsed_uri = urlparse(self.GOOGLE_REDIRECT_URI.strip())
        is_production = self.ENVIRONMENT.strip().lower() == "production"
        allowed_schemes = {"https"} if is_production else {"http", "https"}
        if parsed_uri.scheme.lower() not in allowed_schemes or not parsed_uri.netloc:
            raise ValueError(
                "GOOGLE_REDIRECT_URI must be a valid absolute URL"
                + (" using https in production." if is_production else " (http or https).")
            )

        if not raw_enc_key or not raw_enc_key.strip():
            raise ValueError(
                "TOKEN_ENCRYPTION_KEY must be configured when OAuth is enabled."
            )

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
