"""Pydantic schemas for OAuth & Connected Accounts (Phase 18 — Task 18.5 & P1-C)."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

OAuthPlatform = Literal["web", "android", "ios"]


class OAuthProviderInfo(BaseModel):
    provider: str
    display_name: str
    account_type: str = "personal"
    configured: bool
    supported_platforms: list[OAuthPlatform] = ["web"]
    scopes: list[str]
    capabilities: dict[str, str] = {}
    required_permissions: list[str] = []
    enterprise_only_restrictions: list[str] = []
    limitations: list[str] = []


class OAuthProvidersResponse(BaseModel):
    providers: list[OAuthProviderInfo]


class OAuthAuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    platform: OAuthPlatform = "web"


class OAuthAuthorizeResponse(BaseModel):
    provider: str
    platform: OAuthPlatform = "web"
    authorization_url: str
    expires_at: str


class OAuthCallbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(..., min_length=1, max_length=2048)
    state: str = Field(..., min_length=16, max_length=512)
    platform: OAuthPlatform = "web"

    @field_validator("code", "state")
    @classmethod
    def must_not_be_blank(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Field cannot be empty or whitespace-only.")
        return stripped


class ConnectedAccountResponse(BaseModel):
    id: str
    provider: str
    provider_email: str | None
    provider_email_verified: bool
    display_name: str | None
    avatar_url: str | None
    scopes: list[str]
    status: str
    created_at: str
    updated_at: str
    last_synced_at: str | None


class DisconnectAccountResponse(BaseModel):
    message: str
    disconnected_account_id: str
    upstream_revocation_status: str
