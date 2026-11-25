import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.rate_limit import limiter
from app.core.rbac import CurrentUser
from app.core.security import (
    create_access_token,
    dummy_verify_password,
    generate_refresh_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.database import get_db
from app.models.user import RefreshToken, User, UserSession
from app.schemas.auth import (
    LoginRequest,
    LogoutAllResponse,
    RefreshRequest,
    RegisterRequest,
    RevokeSessionResponse,
    SessionResponse,
    TokenResponse,
    UserResponse,
)
from app.utils.audit import record_audit_event
from app.utils.device import extract_client_metadata

router = APIRouter(prefix="/auth", tags=["authentication"])
settings = get_settings()


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
    record_audit_event(db, actor_id=user.id, action="user.registered", resource=user.id, request=request)
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)):
    generic_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if user is None:
        dummy_verify_password(payload.password)
        raise generic_error

    # If the user is locked or disabled, perform verification to equalize timing,
    # then fail authentication without updating login timestamps or creating sessions.
    is_locked = bool(user.locked_until and user.locked_until > datetime.utcnow())
    is_disabled = not user.is_active

    if is_locked or is_disabled:
        verify_password(payload.password, user.password_hash)
        raise generic_error

    if not verify_password(payload.password, user.password_hash):
        user.failed_login_attempts += 1
        db.commit()
        raise generic_error

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.utcnow()

    # Create UserSession for newly authenticated login
    meta = extract_client_metadata(request)
    now = datetime.utcnow()
    session_id = str(uuid.uuid4())
    session_expires = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    session = UserSession(
        id=session_id,
        user_id=user.id,
        device_name=meta["device_name"],
        client_type=meta["client_type"],
        user_agent=meta["user_agent"],
        ip_address=meta["ip_address"],
        is_active=True,
        created_at=now,
        last_active_at=now,
        expires_at=session_expires,
    )
    db.add(session)

    raw_refresh, refresh_hash, expires_at = generate_refresh_token()
    db.add(RefreshToken(
        session_id=session.id,
        user_id=user.id,
        token_hash=refresh_hash,
        expires_at=expires_at,
    ))
    db.commit()

    access_token = create_access_token(subject=user.id, role=user.role.value, session_id=session.id)
    record_audit_event(db, actor_id=user.id, action="user.login", resource=user.id, request=request)
    return TokenResponse(access_token=access_token, refresh_token=raw_refresh)


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("20/minute")
def refresh(request: Request, payload: RefreshRequest, db: Session = Depends(get_db)):
    # SEC-06: Atomic concurrency control for refresh token rotation.
    # On SQLite, take an immediate transaction lock. On PostgreSQL, row-level locking
    # via with_for_update() serializes concurrent refresh attempts on the exact token row.
    if db.bind and db.bind.dialect.name == "sqlite":
        try:
            db.execute(text("BEGIN IMMEDIATE"))
        except Exception:
            pass

    token_hash = hash_token(payload.refresh_token)
    stored = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_hash == token_hash)
        .with_for_update()
        .first()
    )

    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if stored is None:
        raise unauthorized

    # Replay Detection (SEC-05 / SEC-06): If a previously consumed or revoked refresh token
    # is presented (including by a losing concurrent request whose predecessor already committed),
    # treat this as an indicator of compromise and immediately invalidate the associated session
    # and all refresh tokens in that family.
    if stored.revoked:
        if stored.session_id:
            try:
                session = db.get(UserSession, stored.session_id)
                if session and session.is_active:
                    session.is_active = False
                    db.query(RefreshToken).filter(
                        RefreshToken.session_id == session.id,
                    ).update({"revoked": True})
                    record_audit_event(
                        db,
                        actor_id=stored.user_id,
                        action="security.refresh_token_replayed",
                        resource=session.id,
                        details={
                            "session_id": session.id,
                            "reason": "Replay of revoked or consumed refresh token detected",
                        },
                        request=request,
                    )
                    db.commit()
            except Exception:
                db.rollback()
                raise
        raise unauthorized

    if stored.expires_at < datetime.utcnow():
        raise unauthorized

    user = db.get(User, stored.user_id)
    if user is None or not user.is_active:
        raise unauthorized

    # Session management & validation
    session_id = stored.session_id
    if session_id:
        session = db.get(UserSession, session_id)
        if (
            session is None
            or session.user_id != user.id
            or not session.is_active
            or session.expires_at < datetime.utcnow()
        ):
            raise unauthorized
        session.last_active_at = datetime.utcnow()
    else:
        # Legacy Refresh Token compatibility:
        # If refreshing a legacy token without session_id (or missing session record),
        # create a new UserSession for this device so the client seamlessly transitions into session tracking.
        meta = extract_client_metadata(request)
        now = datetime.utcnow()
        session_id = str(uuid.uuid4())
        session = UserSession(
            id=session_id,
            user_id=user.id,
            device_name=meta["device_name"],
            client_type=meta["client_type"],
            user_agent=meta["user_agent"],
            ip_address=meta["ip_address"],
            is_active=True,
            created_at=now,
            last_active_at=now,
            expires_at=now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
        db.add(session)
        stored.session_id = session.id

    try:
        # Rotate: revoke the used token and issue a new one (prevents replay).
        stored.revoked = True
        new_raw, new_hash, new_expires = generate_refresh_token()
        db.add(RefreshToken(
            session_id=session_id,
            user_id=user.id,
            token_hash=new_hash,
            expires_at=new_expires,
        ))
        db.commit()
    except Exception:
        db.rollback()
        raise

    access_token = create_access_token(subject=user.id, role=user.role.value, session_id=session_id)
    return TokenResponse(access_token=access_token, refresh_token=new_raw)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, payload: RefreshRequest, user: CurrentUser, db: Session = Depends(get_db)):
    # 1. Invalidate the caller's active session and its refresh tokens
    current_sid = getattr(user, "current_session_id", None)
    if current_sid:
        current_session = db.get(UserSession, current_sid)
        if current_session and current_session.user_id == user.id:
            current_session.is_active = False
        db.query(RefreshToken).filter(
            RefreshToken.session_id == current_sid,
            RefreshToken.user_id == user.id,
        ).update({"revoked": True})

    # 2. Invalidate refresh token passed in payload and its session (if separate)
    if payload.refresh_token:
        token_hash = hash_token(payload.refresh_token)
        stored = db.query(RefreshToken).filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.user_id == user.id,
        ).first()
        if stored:
            stored.revoked = True
            if stored.session_id and stored.session_id != current_sid:
                rf_session = db.get(UserSession, stored.session_id)
                if rf_session and rf_session.user_id == user.id:
                    rf_session.is_active = False
                db.query(RefreshToken).filter(
                    RefreshToken.session_id == stored.session_id,
                    RefreshToken.user_id == user.id,
                ).update({"revoked": True})

    db.commit()
    record_audit_event(db, actor_id=user.id, action="user.logout", resource=user.id, request=request)


@router.get("/me", response_model=UserResponse)
def get_me(user: CurrentUser):
    return user


@router.get("/sessions", response_model=list[SessionResponse])
def list_active_sessions(user: CurrentUser, db: Session = Depends(get_db)):
    """List all active, non-expired sessions belonging to the authenticated user."""
    now = datetime.utcnow()
    sessions = (
        db.query(UserSession)
        .filter(
            UserSession.user_id == user.id,
            UserSession.is_active.is_(True),
            UserSession.expires_at > now,
        )
        .order_by(UserSession.last_active_at.desc())
        .all()
    )
    current_sid = getattr(user, "current_session_id", None)
    return [
        SessionResponse(
            id=s.id,
            device_name=s.device_name,
            client_type=s.client_type,
            ip_address=s.ip_address,
            created_at=s.created_at.isoformat(),
            last_active_at=s.last_active_at.isoformat(),
            expires_at=s.expires_at.isoformat(),
            is_current=(s.id == current_sid),
        )
        for s in sessions
    ]


@router.delete("/sessions/{session_id}", response_model=RevokeSessionResponse)
def revoke_session(session_id: str, request: Request, user: CurrentUser, db: Session = Depends(get_db)):
    """Revoke a specific session belonging to the authenticated user."""
    session = db.get(UserSession, session_id)
    if session is None or session.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    session.is_active = False
    # Revoke all associated refresh tokens for this session
    db.query(RefreshToken).filter(
        RefreshToken.session_id == session.id,
        RefreshToken.user_id == user.id,
    ).update({"revoked": True})
    db.commit()

    record_audit_event(
        db,
        actor_id=user.id,
        action="user.session_revoked",
        resource=session_id,
        details={"session_id": session_id, "device_name": session.device_name},
        request=request,
    )
    return RevokeSessionResponse(
        message="Session revoked successfully",
        revoked_session_id=session_id,
    )


@router.post("/logout-all", response_model=LogoutAllResponse)
def logout_all_other_devices(request: Request, user: CurrentUser, db: Session = Depends(get_db)):
    """Deactivate all active sessions for the authenticated user except the current session."""
    current_sid = getattr(user, "current_session_id", None)
    now = datetime.utcnow()

    query = db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.is_active.is_(True),
        UserSession.expires_at > now,
    )
    if current_sid:
        query = query.filter(UserSession.id != current_sid)

    other_sessions = query.all()
    revoked_count = len(other_sessions)

    for s in other_sessions:
        s.is_active = False
        db.query(RefreshToken).filter(
            RefreshToken.session_id == s.id,
            RefreshToken.user_id == user.id,
        ).update({"revoked": True})

    db.commit()
    record_audit_event(
        db,
        actor_id=user.id,
        action="user.logout_all_others",
        details={"revoked_count": revoked_count},
        request=request,
    )
    return LogoutAllResponse(
        message="All other sessions have been revoked successfully.",
        revoked_sessions_count=revoked_count,
    )
