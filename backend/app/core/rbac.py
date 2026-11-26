"""
Authentication and role-based access control dependencies.

Every protected route depends on `get_current_user` (or `require_admin`),
which validates the bearer JWT and loads the user. This is the single choke
point for "who is making this request" — route handlers never trust a
user_id passed in the request body.
"""
from datetime import datetime
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session, joinedload

from app.core.security import decode_access_token
from app.database import get_db
from app.models.organization import OrganizationMembership, OrganizationRole
from app.models.user import User, UserRole, UserSession

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized
    try:
        payload = decode_access_token(credentials.credentials)
        if payload.get("type") != "access":
            raise unauthorized
        user_id = payload.get("sub")
        session_id = payload.get("sid")
    except jwt.PyJWTError:
        raise unauthorized

    if not user_id or not session_id:
        raise unauthorized

    session = (
        db.query(UserSession)
        .filter(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
            UserSession.is_active.is_(True),
            UserSession.expires_at > datetime.utcnow(),
        )
        .options(joinedload(UserSession.user))
        .first()
    )

    if session is None or session.user is None or not session.user.is_active:
        raise unauthorized

    user = session.user
    setattr(user, "current_session_id", session.id)
    setattr(user, "current_session", session)
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_optional_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User | None:
    """
    Returns the authenticated User if valid credentials are provided, or None for anonymous requests.
    If an Authorization header is provided but invalid, revoked, or expired, raises HTTP 401 Unauthorized.
    """
    if "authorization" not in request.headers:
        return None
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return get_current_user(credentials=credentials, db=db)


OptionalCurrentUser = Annotated[User | None, Depends(get_optional_current_user)]


def require_admin(user: CurrentUser) -> User:
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator access required")
    return user


AdminUser = Annotated[User, Depends(require_admin)]


def require_org_member(
    organization_id: str,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
) -> OrganizationMembership:
    """
    Enforce strict tenant isolation: the authenticated user must have an active
    membership in an active `organization_id`. Returns 404 otherwise to prevent
    tenant enumeration / IDOR.
    """
    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.is_active.is_(True),
        )
        .options(joinedload(OrganizationMembership.organization))
        .first()
    )
    if (
        membership is None
        or membership.organization is None
        or not membership.organization.is_active
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    return membership


OrgMember = Annotated[OrganizationMembership, Depends(require_org_member)]


def require_org_admin(membership: OrgMember) -> OrganizationMembership:
    """Require `org_admin` role within the verified organization membership."""
    if membership.role != OrganizationRole.ORG_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization administrator access required",
        )
    return membership


OrgAdmin = Annotated[OrganizationMembership, Depends(require_org_admin)]
