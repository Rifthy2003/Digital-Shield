"""Pydantic schemas for multi-tenant Organizations & Memberships (Phase 19 — Task 19.1)."""
import re

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.organization import OrganizationRole

_DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def slugify_name(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return slug[:128]


class CreateOrganizationRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str | None = Field(default=None, min_length=2, max_length=128)
    primary_domain: str | None = Field(default=None, min_length=3, max_length=255)
    edition: str | None = Field(default=None, max_length=64)

    @field_validator("name")
    @classmethod
    def clean_name(cls, v: str) -> str:
        stripped = v.strip()
        if len(stripped) < 2:
            raise ValueError("Organization name must be at least 2 characters.")
        return stripped

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: str | None) -> str | None:
        if v is None:
            return None
        cleaned = v.strip().lower()
        if not _SLUG_RE.match(cleaned):
            raise ValueError("Slug must contain lowercase letters, numbers, and hyphens only.")
        return cleaned

    @field_validator("primary_domain")
    @classmethod
    def normalize_and_validate_domain(cls, v: str | None) -> str | None:
        if v is None:
            return None
        domain = v.strip().lower()
        if not _DOMAIN_RE.match(domain):
            raise ValueError("Invalid primary domain format.")
        return domain


class UpdateOrganizationRequest(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=255)
    edition: str | None = Field(default=None, max_length=64)

    @field_validator("name")
    @classmethod
    def clean_optional_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if len(stripped) < 2:
            raise ValueError("Organization name must be at least 2 characters.")
        return stripped


class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    primary_domain: str | None
    google_customer_id: str | None
    edition: str | None
    is_active: bool
    my_role: OrganizationRole
    created_at: str
    updated_at: str


class AddOrganizationMemberRequest(BaseModel):
    email: EmailStr
    role: OrganizationRole = OrganizationRole.ORG_VIEWER


class UpdateOrganizationMemberRoleRequest(BaseModel):
    role: OrganizationRole


class OrganizationMemberResponse(BaseModel):
    id: str
    organization_id: str
    user_id: str
    email: str
    full_name: str | None
    role: OrganizationRole
    is_active: bool
    created_at: str
