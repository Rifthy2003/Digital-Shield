"""
Provider-independent OAuth & Security Capability Registry (P1-C).

Separates Personal Consumer Account capabilities from Enterprise/Organization
capabilities so Infora never misrepresents unsupported consumer signals (e.g.,
personal login history, active devices, or provider MFA status) as available.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass


class CapabilityStatus(str, enum.Enum):
    SUPPORTED = "supported"
    SUPPORTED_WITH_RESTRICTIONS = "supported_with_restrictions"
    REQUIRES_ENTERPRISE = "requires_enterprise"
    UNAVAILABLE = "unavailable"
    NOT_VERIFIED = "not_verified"


@dataclass(frozen=True)
class ProviderCapabilities:
    oauth_connection: CapabilityStatus
    identity_verification: CapabilityStatus
    email_availability: CapabilityStatus
    login_history: CapabilityStatus
    new_login_notifications: CapabilityStatus
    device_session_visibility: CapabilityStatus
    mfa_status: CapabilityStatus
    third_party_app_permissions: CapabilityStatus
    token_revocation: CapabilityStatus

    def as_dict(self) -> dict[str, str]:
        return {
            "oauth_connection": self.oauth_connection.value,
            "identity_verification": self.identity_verification.value,
            "email_availability": self.email_availability.value,
            "login_history": self.login_history.value,
            "new_login_notifications": self.new_login_notifications.value,
            "device_session_visibility": self.device_session_visibility.value,
            "mfa_status": self.mfa_status.value,
            "third_party_app_permissions": self.third_party_app_permissions.value,
            "token_revocation": self.token_revocation.value,
        }


@dataclass(frozen=True)
class ProviderRegistryEntry:
    provider: str
    display_name: str
    account_type: str  # "personal" | "enterprise"
    connectable: bool
    capabilities: ProviderCapabilities
    required_permissions: tuple[str, ...]
    enterprise_only_restrictions: tuple[str, ...]
    limitations: tuple[str, ...]


PROVIDER_REGISTRY: dict[str, ProviderRegistryEntry] = {
    "google": ProviderRegistryEntry(
        provider="google",
        display_name="Google",
        account_type="personal",
        connectable=True,
        capabilities=ProviderCapabilities(
            oauth_connection=CapabilityStatus.SUPPORTED,
            identity_verification=CapabilityStatus.SUPPORTED,
            email_availability=CapabilityStatus.SUPPORTED,
            login_history=CapabilityStatus.REQUIRES_ENTERPRISE,
            new_login_notifications=CapabilityStatus.UNAVAILABLE,
            device_session_visibility=CapabilityStatus.REQUIRES_ENTERPRISE,
            mfa_status=CapabilityStatus.REQUIRES_ENTERPRISE,
            third_party_app_permissions=CapabilityStatus.UNAVAILABLE,
            token_revocation=CapabilityStatus.SUPPORTED,
        ),
        required_permissions=("openid", "email", "profile"),
        enterprise_only_restrictions=(
            "Sign-in audit logs, managed devices, and 2-Step Verification reporting require Google Workspace Admin SDK APIs.",
        ),
        limitations=(
            "Personal Google OAuth verifies identity and email only.",
            "Google does not expose personal sign-in history, active devices, or Google 2FA enrollment status through these consumer scopes.",
        ),
    ),
    "microsoft": ProviderRegistryEntry(
        provider="microsoft",
        display_name="Microsoft",
        account_type="personal",
        connectable=True,
        capabilities=ProviderCapabilities(
            oauth_connection=CapabilityStatus.SUPPORTED,
            identity_verification=CapabilityStatus.SUPPORTED,
            email_availability=CapabilityStatus.SUPPORTED,
            login_history=CapabilityStatus.REQUIRES_ENTERPRISE,
            new_login_notifications=CapabilityStatus.UNAVAILABLE,
            device_session_visibility=CapabilityStatus.REQUIRES_ENTERPRISE,
            mfa_status=CapabilityStatus.REQUIRES_ENTERPRISE,
            third_party_app_permissions=CapabilityStatus.UNAVAILABLE,
            token_revocation=CapabilityStatus.UNAVAILABLE,
        ),
        required_permissions=("openid", "profile", "email", "User.Read"),
        enterprise_only_restrictions=(
            "Sign-in logs, device compliance, and authentication method reporting require Microsoft Entra ID organizational tenant permissions.",
        ),
        limitations=(
            "Personal Microsoft OAuth verifies your Microsoft account identity and basic profile only.",
            "Microsoft does not expose private sign-in history, active devices, or Microsoft MFA enrollment status through these personal permissions.",
            "Microsoft personal OAuth does not provide an upstream token revocation endpoint; disconnecting removes Infora's stored tokens locally.",
        ),
    ),
    "google_workspace": ProviderRegistryEntry(
        provider="google_workspace",
        display_name="Google Workspace",
        account_type="enterprise",
        connectable=False,
        capabilities=ProviderCapabilities(
            oauth_connection=CapabilityStatus.REQUIRES_ENTERPRISE,
            identity_verification=CapabilityStatus.SUPPORTED_WITH_RESTRICTIONS,
            email_availability=CapabilityStatus.SUPPORTED_WITH_RESTRICTIONS,
            login_history=CapabilityStatus.REQUIRES_ENTERPRISE,
            new_login_notifications=CapabilityStatus.UNAVAILABLE,
            device_session_visibility=CapabilityStatus.REQUIRES_ENTERPRISE,
            mfa_status=CapabilityStatus.REQUIRES_ENTERPRISE,
            third_party_app_permissions=CapabilityStatus.REQUIRES_ENTERPRISE,
            token_revocation=CapabilityStatus.SUPPORTED,
        ),
        required_permissions=("admin.reports.audit.readonly", "admin.directory.user.readonly"),
        enterprise_only_restrictions=(
            "Requires a Google Workspace organization domain and Super Admin consent.",
        ),
        limitations=(
            "Enterprise Workspace integration is separate from Personal Google accounts and not enabled for personal OAuth linking.",
        ),
    ),
    "microsoft_entra": ProviderRegistryEntry(
        provider="microsoft_entra",
        display_name="Microsoft Entra ID",
        account_type="enterprise",
        connectable=False,
        capabilities=ProviderCapabilities(
            oauth_connection=CapabilityStatus.REQUIRES_ENTERPRISE,
            identity_verification=CapabilityStatus.SUPPORTED_WITH_RESTRICTIONS,
            email_availability=CapabilityStatus.SUPPORTED_WITH_RESTRICTIONS,
            login_history=CapabilityStatus.REQUIRES_ENTERPRISE,
            new_login_notifications=CapabilityStatus.UNAVAILABLE,
            device_session_visibility=CapabilityStatus.REQUIRES_ENTERPRISE,
            mfa_status=CapabilityStatus.REQUIRES_ENTERPRISE,
            third_party_app_permissions=CapabilityStatus.REQUIRES_ENTERPRISE,
            token_revocation=CapabilityStatus.REQUIRES_ENTERPRISE,
        ),
        required_permissions=("AuditLog.Read.All", "User.Read.All", "UserAuthenticationMethod.Read.All"),
        enterprise_only_restrictions=(
            "Requires a Microsoft Entra ID organizational tenant and administrator consent.",
        ),
        limitations=(
            "Enterprise Entra ID integration is separate from Personal Microsoft accounts and not enabled for personal OAuth linking.",
        ),
    ),
}


def get_provider_entry(provider: str) -> ProviderRegistryEntry | None:
    """Return the capability registry entry for `provider`, if known."""
    return PROVIDER_REGISTRY.get(provider)


def list_connectable_providers() -> list[ProviderRegistryEntry]:
    """Return personal OAuth providers supported for user account linking."""
    return [entry for entry in PROVIDER_REGISTRY.values() if entry.connectable]
