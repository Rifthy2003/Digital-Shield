from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.rate_limit import limiter
from app.core.rbac import CurrentUser
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.database import get_db
from app.models.user import RefreshToken, User
from app.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.utils.audit import record_audit_event

router = APIRouter(prefix="/auth", tags=["authentication"])

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
def register(request: Request, payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email.lower()).first()
    if existing:
        # Deliberately generic message — do not reveal whether the email exists.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not create account with the provided details")

    user = User(
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    record_audit_event(db, actor_id=user.id, action="user.registered", resource=user.id)
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)):
    generic_error = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if user is None:
        raise generic_error

    if user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account temporarily locked due to repeated failed logins")

    if not verify_password(payload.password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_login_attempts = 0
        db.commit()
        raise generic_error

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.utcnow()
    db.commit()

    access_token = create_access_token(subject=user.id, role=user.role.value)
    raw_refresh, refresh_hash, expires_at = generate_refresh_token()
    db.add(RefreshToken(user_id=user.id, token_hash=refresh_hash, expires_at=expires_at))
    db.commit()

    record_audit_event(db, actor_id=user.id, action="user.login", resource=user.id)
    return TokenResponse(access_token=access_token, refresh_token=raw_refresh)


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("20/minute")
def refresh(request: Request, payload: RefreshRequest, db: Session = Depends(get_db)):
    token_hash = hash_token(payload.refresh_token)
    stored = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()

    unauthorized = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")
    if stored is None or stored.revoked or stored.expires_at < datetime.utcnow():
        raise unauthorized

    user = db.get(User, stored.user_id)
    if user is None or not user.is_active:
        raise unauthorized

    # Rotate: revoke the used token and issue a new one (prevents replay).
    stored.revoked = True
    new_raw, new_hash, new_expires = generate_refresh_token()
    db.add(RefreshToken(user_id=user.id, token_hash=new_hash, expires_at=new_expires))
    db.commit()

    access_token = create_access_token(subject=user.id, role=user.role.value)
    return TokenResponse(access_token=access_token, refresh_token=new_raw)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(payload: RefreshRequest, user: CurrentUser, db: Session = Depends(get_db)):
    token_hash = hash_token(payload.refresh_token)
    stored = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash, RefreshToken.user_id == user.id).first()
    if stored:
        stored.revoked = True
        db.commit()
    record_audit_event(db, actor_id=user.id, action="user.logout", resource=user.id)


@router.get("/me", response_model=UserResponse)
def get_me(user: CurrentUser):
    return user
