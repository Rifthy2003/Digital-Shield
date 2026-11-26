"""Pydantic schemas for OAuth & Connected Accounts (Phase 18 — Task 18.5)."""
from pydantic import BaseModel, Field, field_validator


class OAuthProviderInfo(BaseModel):
    provider: str
    display_name: str
    account_type: str = "personal"
    configured: bool
    scopes: list[str]
    capabilities: dict[str, str] = {}
    required_permissions: list[str] = []
    enterprise_only_restrictions: list[str] = []
    limitations: list[str] = []


class OAuthProvidersResponse(BaseModel):
    providers: list[OAuthProviderInfo]


class OAuthAuthorizeResponse(BaseModel):
    provider: str
    authorization_url: str
    expires_at: str


class OAuthCallbackRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=2048)
    state: str = Field(..., min_length=16, max_length=512)

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
