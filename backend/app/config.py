"""
Centralized application configuration.

All secrets and environment-specific values are loaded from environment
variables (see .env.example). Nothing sensitive is hardcoded here, and
nothing here should ever be committed with real values filled in.
"""
import logging
from functools import lru_cache
from typing import List

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

    # --- Third-party providers (optional; features degrade honestly if unset) ---
    HIBP_API_KEY: str | None = None  # Have I Been Pwned — breach monitoring
    AI_PROVIDER_API_KEY: str | None = None  # AI assistant backing provider
    AI_PROVIDER_MODEL: str = "not-configured"

    # --- Data retention (days) ---
    MESSAGE_CHECK_RETENTION_DAYS: int = 30
    URL_CHECK_RETENTION_DAYS: int = 90

    # --- Encryption key for OAuth tokens at rest (future use) ---
    # Must be a urlsafe base64-encoded 32-byte key (Fernet-compatible).
    TOKEN_ENCRYPTION_KEY: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
