import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.mfa import MfaChallenge, MfaRecoveryCode
    from app.models.oauth import ConnectedAccount, OAuthState
    from app.models.organization import OrganizationMembership


class UserRole(str, enum.Enum):
    CITIZEN = "citizen"
    ADMIN = "admin"


class User(Base):
    """
    A user account.

    IMPORTANT: password_hash is the ONLY place a credential is stored, and it
    is always an Argon2id hash (see app/core/security.py). Plaintext
    passwords are never persisted or logged.
    """

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.CITIZEN, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mfa_pending_secret_encrypted: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mfa_last_totp_step: Mapped[int | None] = mapped_column(Integer, nullable=True)

    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    oauth_states: Mapped[list["OAuthState"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    mfa_recovery_codes: Mapped[list["MfaRecoveryCode"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    mfa_challenges: Mapped[list["MfaChallenge"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    connected_accounts: Mapped[list["ConnectedAccount"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    organization_memberships: Mapped[list["OrganizationMembership"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class UserSession(Base):
    """
    Tracks an active client session (browser, mobile app, etc.) associated with a user.
    Enables per-device session management and immediate access token invalidation.
    """

    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    device_name: Mapped[str] = mapped_column(String(128), nullable=False)
    client_type: Mapped[str] = mapped_column(String(32), default="web", nullable=False)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    last_active_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)

    user: Mapped["User"] = relationship(back_populates="sessions")
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class RefreshToken(Base):
    """
    Opaque, hashed refresh tokens. The raw token is only ever sent to the
    client once (at issuance) and never stored — only its hash is kept, so a
    database compromise does not hand out valid sessions.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("user_sessions.id", ondelete="CASCADE"), index=True, nullable=True
    )
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    user: Mapped["User"] = relationship(back_populates="refresh_tokens")
    session: Mapped["UserSession | None"] = relationship(back_populates="refresh_tokens")
