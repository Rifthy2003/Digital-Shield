"""
OAuth & Connected Accounts API routes (Phase 18 — Task 18.5).

Security guarantees:
- All endpoints require an authenticated Infora user (`CurrentUser`).
- `OAuthState` is consumed atomically via a single conditional UPDATE before
  external HTTP calls; no DB transaction is held open across Google requests.
- External provider tokens are encrypted via `TokenCipher` and never returned
  to the frontend or logged.
- Multiple Google accounts per Infora user are supported, while one Google
  identity (`sub`) can belong to at most one Infora user.
"""
from datetime import datetime, timedelta
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.crypto import TokenCryptoError
from app.core.rate_limit import limiter
from app.core.rbac import CurrentUser
from app.database import get_db
from app.models.oauth import ConnectedAccount, OAuthState, OAuthToken
from app.schemas.oauth import (
    ConnectedAccountResponse,
    DisconnectAccountResponse,
    OAuthAuthorizeResponse,
    OAuthCallbackRequest,
    OAuthProviderInfo,
    OAuthProvidersResponse,
)
from app.services.oauth_google import (
    GoogleIdTokenValidationError,
    GoogleOAuthError,
    GoogleOAuthNotConfiguredError,
    GoogleOAuthService,
    GoogleTokenRevocationError,
    hash_oauth_value,
)
from app.services.oauth_microsoft import (
    MicrosoftIdTokenValidationError,
    MicrosoftOAuthError,
    MicrosoftOAuthNotConfiguredError,
    MicrosoftOAuthService,
)
from app.services.oauth_registry import list_connectable_providers
from app.utils.audit import record_audit_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/oauth", tags=["oauth"])

OAUTH_STATE_TTL_MINUTES = 10
EXPIRED_STATE_CLEANUP_BATCH_SIZE = 500


def get_google_oauth_service() -> GoogleOAuthService:
    return GoogleOAuthService()


def get_microsoft_oauth_service() -> MicrosoftOAuthService:
    return MicrosoftOAuthService()


def _serialize_connected_account(account: ConnectedAccount) -> ConnectedAccountResponse:
    return ConnectedAccountResponse(
        id=account.id,
        provider=account.provider,
        provider_email=account.provider_email,
        provider_email_verified=account.provider_email_verified,
        display_name=account.display_name,
        avatar_url=account.avatar_url,
        scopes=[s for s in account.scopes.split(" ") if s] if account.scopes else [],
        status=account.status,
        created_at=account.created_at.isoformat(),
        updated_at=account.updated_at.isoformat(),
        last_synced_at=account.last_synced_at.isoformat() if account.last_synced_at else None,
    )


def cleanup_expired_oauth_states(db: Session, batch_size: int = EXPIRED_STATE_CLEANUP_BATCH_SIZE) -> int:
    """
    Bounded cleanup of expired `OAuthState` rows.
    Deletes only rows where `expires_at < now`; never touches active states,
    `ConnectedAccount`, or `OAuthToken` records.
    """
    now = datetime.utcnow()
    expired_ids = [
        row[0]
        for row in db.query(OAuthState.id)
        .filter(OAuthState.expires_at < now)
        .limit(batch_size)
        .all()
    ]
    if not expired_ids:
        return 0
    deleted = (
        db.query(OAuthState)
        .filter(OAuthState.id.in_(expired_ids))
        .delete(synchronize_session=False)
    )
    db.commit()
    return int(deleted or 0)


@router.get("/providers", response_model=OAuthProvidersResponse)
def list_oauth_providers(user: CurrentUser):
    """List supported OAuth providers, configuration status, and capability matrix."""
    settings = get_settings()
    token_key_ok = bool(settings.TOKEN_ENCRYPTION_KEY and settings.TOKEN_ENCRYPTION_KEY.strip())
    configured_map = {
        "google": bool(
            settings.google_oauth_enabled
            and settings.GOOGLE_CLIENT_ID
            and settings.GOOGLE_CLIENT_SECRET
            and settings.GOOGLE_REDIRECT_URI
            and token_key_ok
        ),
        "microsoft": bool(
            settings.microsoft_oauth_enabled
            and settings.MICROSOFT_CLIENT_ID
            and settings.MICROSOFT_CLIENT_SECRET
            and settings.MICROSOFT_REDIRECT_URI
            and token_key_ok
        ),
    }
    return OAuthProvidersResponse(
        providers=[
            OAuthProviderInfo(
                provider=entry.provider,
                display_name=entry.display_name,
                account_type=entry.account_type,
                configured=configured_map.get(entry.provider, False),
                scopes=list(entry.required_permissions),
                capabilities=entry.capabilities.as_dict(),
                required_permissions=list(entry.required_permissions),
                enterprise_only_restrictions=list(entry.enterprise_only_restrictions),
                limitations=list(entry.limitations),
            )
            for entry in list_connectable_providers()
        ]
    )


@router.get("/accounts", response_model=list[ConnectedAccountResponse])
def list_connected_accounts(user: CurrentUser, db: Session = Depends(get_db)):
    """List connected OAuth accounts belonging to the authenticated user."""
    accounts = (
        db.query(ConnectedAccount)
        .filter(ConnectedAccount.user_id == user.id)
        .order_by(ConnectedAccount.created_at.desc())
        .all()
    )
    return [_serialize_connected_account(acc) for acc in accounts]


@router.post("/google/authorize", response_model=OAuthAuthorizeResponse)
@limiter.limit("10/minute")
def authorize_google(
    request: Request,
    user: CurrentUser,
    db: Session = Depends(get_db),
    google_svc: GoogleOAuthService = Depends(get_google_oauth_service),
):
    """Initiate Google OAuth 2.0 / OIDC authorization with PKCE S256 and single-use state."""
    cleanup_expired_oauth_states(db)

    try:
        artifacts = google_svc.build_authorization_request()
    except GoogleOAuthNotConfiguredError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google OAuth is not configured for this deployment",
        ) from exc

    now = datetime.utcnow()
    expires_at = now + timedelta(minutes=OAUTH_STATE_TTL_MINUTES)

    oauth_state = OAuthState(
        user_id=user.id,
        provider="google",
        state_hash=artifacts.state_hash,
        nonce_hash=artifacts.nonce_hash,
        code_verifier_encrypted=artifacts.code_verifier_encrypted,
        redirect_uri=artifacts.redirect_uri,
        used=False,
        expires_at=expires_at,
    )
    db.add(oauth_state)
    db.commit()

    record_audit_event(
        db,
        actor_id=user.id,
        action="oauth.authorization_started",
        details={"provider": "google"},
        request=request,
    )

    return OAuthAuthorizeResponse(
        provider="google",
        authorization_url=artifacts.authorization_url,
        expires_at=expires_at.isoformat(),
    )


@router.post("/google/callback", response_model=ConnectedAccountResponse)
@limiter.limit("10/minute")
async def google_callback(
    request: Request,
    payload: OAuthCallbackRequest,
    user: CurrentUser,
    db: Session = Depends(get_db),
    google_svc: GoogleOAuthService = Depends(get_google_oauth_service),
):
    """
    Complete Google OAuth callback: atomically consume single-use state,
    exchange code + PKCE verifier, verify OIDC id_token, and link account.
    """
    now = datetime.utcnow()
    state_hash = hash_oauth_value(payload.state)

    # Atomic single-use state consumption before any external HTTP call.
    consume_stmt = (
        update(OAuthState)
        .where(
            OAuthState.state_hash == state_hash,
            OAuthState.user_id == user.id,
            OAuthState.provider == "google",
            OAuthState.used.is_(False),
            OAuthState.expires_at > now,
        )
        .values(used=True)
    )
    result = db.execute(consume_stmt)
    if result.rowcount != 1:
        db.rollback()
        record_audit_event(
            db,
            actor_id=user.id,
            action="oauth.callback_failed",
            details={"provider": "google", "reason": "invalid_or_expired_state"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or already used OAuth state",
        )

    consumed_state = (
        db.query(OAuthState)
        .filter(OAuthState.state_hash == state_hash)
        .first()
    )
    if consumed_state is None:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or already used OAuth state",
        )

    code_verifier_encrypted = consumed_state.code_verifier_encrypted
    nonce_hash = consumed_state.nonce_hash or ""
    db.commit()

    # External HTTP exchange happens outside any open DB transaction.
    try:
        cb_result = await google_svc.exchange_code_for_tokens(
            code=payload.code,
            code_verifier_encrypted=code_verifier_encrypted,
            expected_nonce_hash=nonce_hash,
        )
    except GoogleIdTokenValidationError as exc:
        record_audit_event(
            db,
            actor_id=user.id,
            action="oauth.callback_failed",
            details={"provider": "google", "reason": "id_token_validation_failed"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not verify Google identity",
        ) from exc
    except GoogleOAuthNotConfiguredError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google OAuth is not configured for this deployment",
        ) from exc
    except (GoogleOAuthError, TokenCryptoError) as exc:
        record_audit_event(
            db,
            actor_id=user.id,
            action="oauth.callback_failed",
            details={"provider": "google", "reason": "provider_exchange_failed"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not complete Google account linking",
        ) from exc

    identity = cb_result.identity
    tokens = cb_result.tokens
    sync_time = datetime.utcnow()

    existing = (
        db.query(ConnectedAccount)
        .filter(
            ConnectedAccount.provider == "google",
            ConnectedAccount.provider_user_id == identity.provider_user_id,
        )
        .first()
    )

    if existing is not None and existing.user_id != user.id:
        record_audit_event(
            db,
            actor_id=user.id,
            action="oauth.callback_failed",
            details={"provider": "google", "reason": "identity_conflict"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This external account cannot be linked",
        )

    try:
        if existing is not None:
            account = existing
            account.provider_email = identity.email
            account.provider_email_verified = identity.email_verified
            account.display_name = identity.display_name
            account.avatar_url = identity.avatar_url
            account.scopes = tokens.scopes
            account.status = "active"
            account.last_synced_at = sync_time

            if account.token is not None:
                account.token.access_token_encrypted = tokens.access_token_encrypted
                if tokens.refresh_token_encrypted is not None:
                    account.token.refresh_token_encrypted = tokens.refresh_token_encrypted
                account.token.encryption_key_id = tokens.encryption_key_id
                account.token.token_type = tokens.token_type
                account.token.expires_at = tokens.expires_at
            else:
                db.add(
                    OAuthToken(
                        connected_account_id=account.id,
                        access_token_encrypted=tokens.access_token_encrypted,
                        refresh_token_encrypted=tokens.refresh_token_encrypted,
                        encryption_key_id=tokens.encryption_key_id,
                        token_type=tokens.token_type,
                        expires_at=tokens.expires_at,
                    )
                )
        else:
            account = ConnectedAccount(
                user_id=user.id,
                provider="google",
                provider_user_id=identity.provider_user_id,
                provider_email=identity.email,
                provider_email_verified=identity.email_verified,
                display_name=identity.display_name,
                avatar_url=identity.avatar_url,
                scopes=tokens.scopes,
                status="active",
                last_synced_at=sync_time,
            )
            db.add(account)
            db.flush()
            db.add(
                OAuthToken(
                    connected_account_id=account.id,
                    access_token_encrypted=tokens.access_token_encrypted,
                    refresh_token_encrypted=tokens.refresh_token_encrypted,
                    encryption_key_id=tokens.encryption_key_id,
                    token_type=tokens.token_type,
                    expires_at=tokens.expires_at,
                )
            )
        db.commit()
        db.refresh(account)
    except IntegrityError as exc:
        db.rollback()
        record_audit_event(
            db,
            actor_id=user.id,
            action="oauth.callback_failed",
            details={"provider": "google", "reason": "identity_conflict"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This external account cannot be linked",
        ) from exc

    record_audit_event(
        db,
        actor_id=user.id,
        action="oauth.account_linked",
        resource=account.id,
        details={"provider": "google", "connected_account_id": account.id},
        request=request,
    )

    return _serialize_connected_account(account)


@router.delete("/accounts/{account_id}", response_model=DisconnectAccountResponse)
async def disconnect_account(
    account_id: str,
    request: Request,
    user: CurrentUser,
    db: Session = Depends(get_db),
    google_svc: GoogleOAuthService = Depends(get_google_oauth_service),
):
    """
    Disconnect an owned OAuth account: attempt upstream revocation, then
    always delete local `OAuthToken` and `ConnectedAccount` credentials.
    """
    account = db.get(ConnectedAccount, account_id)
    if account is None or account.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connected account not found",
        )

    provider = account.provider
    encrypted_token = None
    if account.token is not None:
        encrypted_token = account.token.refresh_token_encrypted or account.token.access_token_encrypted

    upstream_status = "skipped"
    if provider == "microsoft":
        upstream_status = "unsupported"
    elif encrypted_token and provider == "google":
        try:
            await google_svc.revoke_token(encrypted_token)
            upstream_status = "revoked"
        except (GoogleTokenRevocationError, GoogleOAuthNotConfiguredError, TokenCryptoError):
            upstream_status = "failed"
            record_audit_event(
                db,
                actor_id=user.id,
                action="oauth.revocation_failed",
                resource=account_id,
                details={"provider": provider, "connected_account_id": account_id},
                request=request,
            )

    db.delete(account)
    db.commit()

    record_audit_event(
        db,
        actor_id=user.id,
        action="oauth.account_disconnected",
        resource=account_id,
        details={
            "provider": provider,
            "connected_account_id": account_id,
            "upstream_revocation_status": upstream_status,
        },
        request=request,
    )

    return DisconnectAccountResponse(
        message="Connected account disconnected",
        disconnected_account_id=account_id,
        upstream_revocation_status=upstream_status,
    )


def _start_provider_authorization(
    *,
    provider: str,
    display_name: str,
    request: Request,
    user: CurrentUser,
    db: Session,
    svc: GoogleOAuthService | MicrosoftOAuthService,
) -> OAuthAuthorizeResponse:
    cleanup_expired_oauth_states(db)
    try:
        artifacts = svc.build_authorization_request()
    except (GoogleOAuthNotConfiguredError, MicrosoftOAuthNotConfiguredError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{display_name} OAuth is not configured for this deployment",
        ) from exc

    now = datetime.utcnow()
    expires_at = now + timedelta(minutes=OAUTH_STATE_TTL_MINUTES)
    db.add(
        OAuthState(
            user_id=user.id,
            provider=provider,
            state_hash=artifacts.state_hash,
            nonce_hash=artifacts.nonce_hash,
            code_verifier_encrypted=artifacts.code_verifier_encrypted,
            redirect_uri=artifacts.redirect_uri,
            used=False,
            expires_at=expires_at,
        )
    )
    db.commit()

    record_audit_event(
        db,
        actor_id=user.id,
        action="oauth.authorization_started",
        details={"provider": provider},
        request=request,
    )
    return OAuthAuthorizeResponse(
        provider=provider,
        authorization_url=artifacts.authorization_url,
        expires_at=expires_at.isoformat(),
    )


async def _complete_provider_callback(
    *,
    provider: str,
    display_name: str,
    request: Request,
    payload: OAuthCallbackRequest,
    user: CurrentUser,
    db: Session,
    svc: GoogleOAuthService | MicrosoftOAuthService,
) -> ConnectedAccountResponse:
    now = datetime.utcnow()
    state_hash = hash_oauth_value(payload.state)

    result = db.execute(
        update(OAuthState)
        .where(
            OAuthState.state_hash == state_hash,
            OAuthState.user_id == user.id,
            OAuthState.provider == provider,
            OAuthState.used.is_(False),
            OAuthState.expires_at > now,
        )
        .values(used=True)
    )
    if result.rowcount != 1:
        db.rollback()
        record_audit_event(
            db,
            actor_id=user.id,
            action="oauth.callback_failed",
            details={"provider": provider, "reason": "invalid_or_expired_state"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or already used OAuth state",
        )

    consumed_state = db.query(OAuthState).filter(OAuthState.state_hash == state_hash).first()
    if consumed_state is None:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or already used OAuth state",
        )

    code_verifier_encrypted = consumed_state.code_verifier_encrypted
    nonce_hash = consumed_state.nonce_hash or ""
    db.commit()

    try:
        cb_result = await svc.exchange_code_for_tokens(
            code=payload.code,
            code_verifier_encrypted=code_verifier_encrypted,
            expected_nonce_hash=nonce_hash,
        )
    except (GoogleIdTokenValidationError, MicrosoftIdTokenValidationError) as exc:
        record_audit_event(
            db,
            actor_id=user.id,
            action="oauth.callback_failed",
            details={"provider": provider, "reason": "id_token_validation_failed"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not verify {display_name} identity",
        ) from exc
    except (GoogleOAuthNotConfiguredError, MicrosoftOAuthNotConfiguredError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{display_name} OAuth is not configured for this deployment",
        ) from exc
    except (GoogleOAuthError, MicrosoftOAuthError, TokenCryptoError) as exc:
        record_audit_event(
            db,
            actor_id=user.id,
            action="oauth.callback_failed",
            details={"provider": provider, "reason": "provider_exchange_failed"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not complete {display_name} account linking",
        ) from exc

    identity = cb_result.identity
    tokens = cb_result.tokens
    sync_time = datetime.utcnow()

    existing = (
        db.query(ConnectedAccount)
        .filter(
            ConnectedAccount.provider == provider,
            ConnectedAccount.provider_user_id == identity.provider_user_id,
        )
        .first()
    )
    if existing is not None and existing.user_id != user.id:
        record_audit_event(
            db,
            actor_id=user.id,
            action="oauth.callback_failed",
            details={"provider": provider, "reason": "identity_conflict"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This external account cannot be linked",
        )

    try:
        if existing is not None:
            account = existing
            account.provider_email = identity.email
            account.provider_email_verified = identity.email_verified
            account.display_name = identity.display_name
            account.avatar_url = identity.avatar_url
            account.scopes = tokens.scopes
            account.status = "active"
            account.last_synced_at = sync_time
            if account.token is not None:
                account.token.access_token_encrypted = tokens.access_token_encrypted
                if tokens.refresh_token_encrypted is not None:
                    account.token.refresh_token_encrypted = tokens.refresh_token_encrypted
                account.token.encryption_key_id = tokens.encryption_key_id
                account.token.token_type = tokens.token_type
                account.token.expires_at = tokens.expires_at
            else:
                db.add(
                    OAuthToken(
                        connected_account_id=account.id,
                        access_token_encrypted=tokens.access_token_encrypted,
                        refresh_token_encrypted=tokens.refresh_token_encrypted,
                        encryption_key_id=tokens.encryption_key_id,
                        token_type=tokens.token_type,
                        expires_at=tokens.expires_at,
                    )
                )
        else:
            account = ConnectedAccount(
                user_id=user.id,
                provider=provider,
                provider_user_id=identity.provider_user_id,
                provider_email=identity.email,
                provider_email_verified=identity.email_verified,
                display_name=identity.display_name,
                avatar_url=identity.avatar_url,
                scopes=tokens.scopes,
                status="active",
                last_synced_at=sync_time,
            )
            db.add(account)
            db.flush()
            db.add(
                OAuthToken(
                    connected_account_id=account.id,
                    access_token_encrypted=tokens.access_token_encrypted,
                    refresh_token_encrypted=tokens.refresh_token_encrypted,
                    encryption_key_id=tokens.encryption_key_id,
                    token_type=tokens.token_type,
                    expires_at=tokens.expires_at,
                )
            )
        db.commit()
        db.refresh(account)
    except IntegrityError as exc:
        db.rollback()
        record_audit_event(
            db,
            actor_id=user.id,
            action="oauth.callback_failed",
            details={"provider": provider, "reason": "identity_conflict"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This external account cannot be linked",
        ) from exc

    record_audit_event(
        db,
        actor_id=user.id,
        action="oauth.account_linked",
        resource=account.id,
        details={"provider": provider, "connected_account_id": account.id},
        request=request,
    )
    return _serialize_connected_account(account)


@router.post("/microsoft/authorize", response_model=OAuthAuthorizeResponse)
@limiter.limit("10/minute")
def authorize_microsoft(
    request: Request,
    user: CurrentUser,
    db: Session = Depends(get_db),
    microsoft_svc: MicrosoftOAuthService = Depends(get_microsoft_oauth_service),
):
    """Initiate Microsoft Personal Account OAuth 2.0 / OIDC authorization with PKCE S256."""
    return _start_provider_authorization(
        provider="microsoft",
        display_name="Microsoft",
        request=request,
        user=user,
        db=db,
        svc=microsoft_svc,
    )


@router.post("/microsoft/callback", response_model=ConnectedAccountResponse)
@limiter.limit("10/minute")
async def microsoft_callback(
    request: Request,
    payload: OAuthCallbackRequest,
    user: CurrentUser,
    db: Session = Depends(get_db),
    microsoft_svc: MicrosoftOAuthService = Depends(get_microsoft_oauth_service),
):
    """Complete Microsoft Personal Account OAuth callback and link identity."""
    return await _complete_provider_callback(
        provider="microsoft",
        display_name="Microsoft",
        request=request,
        payload=payload,
        user=user,
        db=db,
        svc=microsoft_svc,
    )


@router.post("/{provider}/authorize")
def authorize_unsupported_provider(provider: str, user: CurrentUser):
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Unsupported OAuth provider",
    )


@router.post("/{provider}/callback")
def callback_unsupported_provider(provider: str, user: CurrentUser):
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Unsupported OAuth provider",
    )
