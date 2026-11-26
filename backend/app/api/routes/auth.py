import re
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import delete, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.crypto import TokenDecryptionError, TokenEncryptionConfigError
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
from app.models.mfa import MfaChallenge, MfaRecoveryCode
from app.models.user import RefreshToken, User, UserSession
from app.schemas.auth import (
    LoginRequest,
    LogoutAllResponse,
    MfaCodeRequest,
    MfaDisableRequest,
    MfaDisableResponse,
    MfaEnrollStartResponse,
    MfaEnrollVerifyResponse,
    MfaLoginVerifyRequest,
    MfaRecoveryCodesResponse,
    MfaRegenerateRecoveryCodesRequest,
    MfaStatusResponse,
    RefreshRequest,
    RegisterRequest,
    RevokeSessionResponse,
    SessionResponse,
    TokenResponse,
    UserResponse,
)
from app.services.mfa import (
    build_provisioning_uri,
    claim_totp_step,
    consume_mfa_challenge,
    consume_recovery_code,
    count_remaining_recovery_codes,
    create_mfa_challenge,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    replace_recovery_codes,
    verify_totp_code,
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


def _issue_session_tokens(db: Session, user: User, request: Request) -> TokenResponse:
    """Create a UserSession, RefreshToken, and access JWT for an authenticated user."""
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
    return TokenResponse(access_token=access_token, refresh_token=raw_refresh)


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

    if user.mfa_enabled:
        if not user.mfa_secret_encrypted:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="MFA configuration is unavailable for this account",
            )
        challenge_token = create_mfa_challenge(db, user.id)
        db.commit()
        record_audit_event(db, actor_id=user.id, action="mfa.challenge_issued", resource=user.id, request=request)
        return TokenResponse(mfa_required=True, mfa_challenge_token=challenge_token)

    user.last_login_at = datetime.utcnow()
    tokens = _issue_session_tokens(db, user, request)
    record_audit_event(db, actor_id=user.id, action="user.login", resource=user.id, request=request)
    return tokens


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


@router.get("/mfa/status", response_model=MfaStatusResponse)
def get_mfa_status(user: CurrentUser, db: Session = Depends(get_db)):
    """Return the Infora account MFA status and remaining recovery code count."""
    remaining = count_remaining_recovery_codes(db, user.id) if user.mfa_enabled else 0
    return MfaStatusResponse(mfa_enabled=user.mfa_enabled, recovery_codes_remaining=remaining)


@router.post("/mfa/enroll/start", response_model=MfaEnrollStartResponse)
@limiter.limit("5/minute")
def start_mfa_enrollment(request: Request, user: CurrentUser, db: Session = Depends(get_db)):
    """Begin TOTP MFA enrollment for the authenticated Infora user."""
    if user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Multi-factor authentication is already enabled",
        )

    secret = generate_totp_secret()
    try:
        encrypted_secret = encrypt_totp_secret(secret)
    except TokenEncryptionConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MFA encryption is not configured on this server",
        ) from exc

    user.mfa_pending_secret_encrypted = encrypted_secret
    user.mfa_pending_expires_at = datetime.utcnow() + timedelta(minutes=settings.MFA_PENDING_EXPIRE_MINUTES)
    db.commit()

    record_audit_event(db, actor_id=user.id, action="mfa.enrollment_started", resource=user.id, request=request)
    return MfaEnrollStartResponse(
        provisioning_uri=build_provisioning_uri(secret, user.email),
        secret=secret,
        issuer=settings.MFA_ISSUER_NAME,
        account_name=user.email,
    )


@router.post("/mfa/enroll/cancel", status_code=status.HTTP_204_NO_CONTENT)
def cancel_mfa_enrollment(request: Request, user: CurrentUser, db: Session = Depends(get_db)):
    """Clear any abandoned pending TOTP MFA enrollment for the authenticated user."""
    if user.mfa_pending_secret_encrypted or user.mfa_pending_expires_at:
        user.mfa_pending_secret_encrypted = None
        user.mfa_pending_expires_at = None
        db.commit()
        record_audit_event(db, actor_id=user.id, action="mfa.enrollment_cancelled", resource=user.id, request=request)


@router.post("/mfa/enroll/verify", response_model=MfaEnrollVerifyResponse)
@limiter.limit("10/minute")
def verify_mfa_enrollment(
    request: Request,
    payload: MfaCodeRequest,
    user: CurrentUser,
    db: Session = Depends(get_db),
):
    """Confirm TOTP enrollment with a valid 6-digit code and issue one-time recovery codes."""
    if user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Multi-factor authentication is already enabled",
        )
    if not user.mfa_pending_secret_encrypted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending MFA enrollment found. Start enrollment first.",
        )
    if user.mfa_pending_expires_at and user.mfa_pending_expires_at <= datetime.utcnow():
        user.mfa_pending_secret_encrypted = None
        user.mfa_pending_expires_at = None
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pending MFA enrollment has expired. Start enrollment again.",
        )

    try:
        secret = decrypt_totp_secret(user.mfa_pending_secret_encrypted)
    except (TokenEncryptionConfigError, TokenDecryptionError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to process MFA secret",
        ) from exc

    matched_step = verify_totp_code(secret, payload.code, last_totp_step=None)
    if matched_step is None:
        record_audit_event(db, actor_id=user.id, action="mfa.enrollment_failed", resource=user.id, request=request)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )

    user.mfa_secret_encrypted = user.mfa_pending_secret_encrypted
    user.mfa_pending_secret_encrypted = None
    user.mfa_pending_expires_at = None
    user.mfa_enabled = True
    user.mfa_last_totp_step = matched_step
    recovery_codes = replace_recovery_codes(db, user.id)
    db.commit()

    record_audit_event(db, actor_id=user.id, action="mfa.enabled", resource=user.id, request=request)
    return MfaEnrollVerifyResponse(mfa_enabled=True, recovery_codes=recovery_codes)


@router.post("/mfa/login-verify", response_model=TokenResponse)
@limiter.limit("10/minute")
def verify_mfa_login(
    request: Request,
    payload: MfaLoginVerifyRequest,
    db: Session = Depends(get_db),
):
    """Verify a 6-digit TOTP code or one-time recovery code to complete MFA login."""
    generic_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired MFA verification",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token_hash = hash_token(payload.challenge_token.strip())
    now = datetime.utcnow()
    challenge = (
        db.query(MfaChallenge)
        .filter(
            MfaChallenge.challenge_hash == token_hash,
            MfaChallenge.used.is_(False),
            MfaChallenge.expires_at > now,
        )
        .first()
    )
    if challenge is None:
        raise generic_error

    user = db.get(User, challenge.user_id)
    if user is None or not user.is_active or not user.mfa_enabled or not user.mfa_secret_encrypted:
        raise generic_error

    is_locked = bool(user.locked_until and user.locked_until > now)
    if is_locked:
        raise generic_error

    try:
        secret = decrypt_totp_secret(user.mfa_secret_encrypted)
    except (TokenEncryptionConfigError, TokenDecryptionError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MFA verification is temporarily unavailable",
        ) from exc

    cleaned_code = payload.code.strip()
    verified_method: str | None = None
    matched_step: int | None = None

    if re.fullmatch(r"\d{6}", cleaned_code):
        matched_step = verify_totp_code(secret, cleaned_code, last_totp_step=user.mfa_last_totp_step)
        if matched_step is not None and claim_totp_step(db, user.id, matched_step):
            verified_method = "totp"
    else:
        if consume_recovery_code(db, user.id, cleaned_code):
            verified_method = "recovery_code"

    if verified_method is None:
        db.rollback()
        record_audit_event(db, actor_id=user.id, action="mfa.login_failed", resource=user.id, request=request)
        raise generic_error

    consumed = consume_mfa_challenge(db, payload.challenge_token)
    if consumed is None:
        db.rollback()
        raise generic_error

    user.last_login_at = datetime.utcnow()

    tokens = _issue_session_tokens(db, user, request)
    if verified_method == "recovery_code":
        record_audit_event(db, actor_id=user.id, action="mfa.recovery_code_used", resource=user.id, request=request)
    record_audit_event(
        db,
        actor_id=user.id,
        action="mfa.login_verified",
        resource=user.id,
        details={"method": verified_method},
        request=request,
    )
    return tokens


@router.post("/mfa/recovery-codes/regenerate", response_model=MfaRecoveryCodesResponse)
@limiter.limit("5/minute")
def regenerate_recovery_codes(
    request: Request,
    payload: MfaRegenerateRecoveryCodesRequest,
    user: CurrentUser,
    db: Session = Depends(get_db),
):
    """Regenerate one-time MFA recovery codes after re-authenticating with password and TOTP."""
    if not user.mfa_enabled or not user.mfa_secret_encrypted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Multi-factor authentication is not enabled",
        )

    if not verify_password(payload.current_password, user.password_hash):
        record_audit_event(
            db, actor_id=user.id, action="mfa.recovery_codes_regenerate_failed", resource=user.id, request=request
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    try:
        secret = decrypt_totp_secret(user.mfa_secret_encrypted)
    except (TokenEncryptionConfigError, TokenDecryptionError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to process MFA secret",
        ) from exc

    matched_step = verify_totp_code(secret, payload.code, last_totp_step=user.mfa_last_totp_step)
    if matched_step is None or not claim_totp_step(db, user.id, matched_step):
        db.rollback()
        record_audit_event(
            db, actor_id=user.id, action="mfa.recovery_codes_regenerate_failed", resource=user.id, request=request
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid verification code")

    codes = replace_recovery_codes(db, user.id)
    db.commit()

    record_audit_event(
        db,
        actor_id=user.id,
        action="mfa.recovery_codes_regenerated",
        resource=user.id,
        request=request,
    )
    return MfaRecoveryCodesResponse(recovery_codes=codes)


@router.post("/mfa/disable", response_model=MfaDisableResponse)
@limiter.limit("5/minute")
def disable_mfa(
    request: Request,
    payload: MfaDisableRequest,
    user: CurrentUser,
    db: Session = Depends(get_db),
):
    """Disable TOTP MFA after verifying current password and a valid TOTP or recovery code."""
    if not user.mfa_enabled or not user.mfa_secret_encrypted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Multi-factor authentication is not enabled",
        )

    if not verify_password(payload.current_password, user.password_hash):
        record_audit_event(db, actor_id=user.id, action="mfa.disable_failed", resource=user.id, request=request)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    try:
        secret = decrypt_totp_secret(user.mfa_secret_encrypted)
    except (TokenEncryptionConfigError, TokenDecryptionError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to process MFA secret",
        ) from exc

    cleaned_code = payload.code.strip()
    verified = False
    if re.fullmatch(r"\d{6}", cleaned_code):
        matched_step = verify_totp_code(secret, cleaned_code, last_totp_step=user.mfa_last_totp_step)
        if matched_step is not None and claim_totp_step(db, user.id, matched_step):
            verified = True
    elif consume_recovery_code(db, user.id, cleaned_code):
        verified = True

    if not verified:
        db.rollback()
        record_audit_event(db, actor_id=user.id, action="mfa.disable_failed", resource=user.id, request=request)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid verification code")

    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    user.mfa_pending_secret_encrypted = None
    user.mfa_pending_expires_at = None
    user.mfa_last_totp_step = None
    db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    db.execute(delete(MfaChallenge).where(MfaChallenge.user_id == user.id))

    current_sid = getattr(user, "current_session_id", None)
    now = datetime.utcnow()
    session_query = db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.is_active.is_(True),
        UserSession.expires_at > now,
    )
    if current_sid:
        session_query = session_query.filter(UserSession.id != current_sid)
    other_sessions = session_query.all()
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
        action="mfa.disabled",
        resource=user.id,
        details={"revoked_other_sessions": len(other_sessions)},
        request=request,
    )
    return MfaDisableResponse(
        mfa_enabled=False,
        revoked_sessions_count=len(other_sessions),
        message="Multi-factor authentication has been disabled.",
    )
