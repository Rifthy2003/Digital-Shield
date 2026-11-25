"""
OAuth & Connected Account database models (Phase 18 — Task 18.3).

Security guarantees:
- `OAuthState` stores only `SHA-256(state)` and `SHA-256(nonce)`, plus the
  Fernet-encrypted PKCE `code_verifier`. Raw state and plaintext verifiers are
  never persisted.
- `ConnectedAccount` stores provider identity metadata only and enforces
  `UNIQUE(provider, provider_user_id)` (one external account cannot belong to
  multiple Infora users) while allowing one Infora user to link multiple
  accounts from the same provider.
- `OAuthToken` stores only encrypted ciphertext (`access_token_encrypted`,
  `refresh_token_encrypted`) and tracks `encryption_key_id` for rotation.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class OAuthState(Base):
    """Short-lived, single-use OAuth CSRF state & PKCE verifier store."""

    __tablename__ = "oauth_states"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    state_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    nonce_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    code_verifier_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    user: Mapped["User"] = relationship(back_populates="oauth_states")


class ConnectedAccount(Base):
    """External OAuth/OIDC provider identity linked to an Infora User."""

    __tablename__ = "connected_accounts"
    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_connected_accounts_provider_user"),
        UniqueConstraint("user_id", "provider", "provider_user_id", name="uq_connected_accounts_user_provider_user"),
        Index("ix_connected_accounts_user_provider", "user_id", "provider"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    provider: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    provider_user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    provider_email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    scopes: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship(back_populates="connected_accounts")
    token: Mapped["OAuthToken | None"] = relationship(
        back_populates="connected_account", uselist=False, cascade="all, delete-orphan"
    )


class OAuthToken(Base):
    """Encrypted OAuth provider tokens at rest; never exposed in API responses."""

    __tablename__ = "oauth_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    connected_account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("connected_accounts.id", ondelete="CASCADE"), unique=True, index=True, nullable=False
    )
    access_token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    refresh_token_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    encryption_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    token_type: Mapped[str] = mapped_column(String(32), default="Bearer", nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    connected_account: Mapped["ConnectedAccount"] = relationship(back_populates="token")
