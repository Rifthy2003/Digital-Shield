import re

from pydantic import BaseModel, EmailStr, Field, field_validator


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., max_length=128)
    full_name: str | None = None

    @field_validator("password")
    @classmethod
    def password_must_be_reasonably_strong(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters long")
        if len(v) > 128:
            raise ValueError("Password must be at most 128 characters long")
        if not re.search(r"[A-Z]", v) or not re.search(r"[a-z]", v) or not re.search(r"\d", v):
            raise ValueError("Password must include uppercase, lowercase, and a number")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., max_length=128)

    @field_validator("password")
    @classmethod
    def password_must_not_exceed_max_length(cls, v: str) -> str:
        if len(v) > 128:
            raise ValueError("Password must be at most 128 characters long")
        return v


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    full_name: str | None
    role: str
    is_email_verified: bool
    mfa_enabled: bool

    class Config:
        from_attributes = True


class SessionResponse(BaseModel):
    id: str
    device_name: str
    client_type: str
    ip_address: str | None
    created_at: str
    last_active_at: str
    expires_at: str
    is_current: bool

    class Config:
        from_attributes = True


class RevokeSessionResponse(BaseModel):
    message: str
    revoked_session_id: str


class LogoutAllResponse(BaseModel):
    message: str
    revoked_sessions_count: int


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_must_be_reasonably_strong(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters long")
        return v
