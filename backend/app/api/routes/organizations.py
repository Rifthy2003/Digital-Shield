"""
Organization & Membership API routes (Phase 19 — Task 19.1).

Enforces strict tenant isolation via `OrgMember` and `OrgAdmin` dependencies
(requiring active memberships on active organizations) and audits all mutations.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.core.rbac import CurrentUser, OrgAdmin, OrgMember
from app.database import get_db
from app.models.organization import Organization, OrganizationMembership, OrganizationRole
from app.models.user import User
from app.schemas.organization import (
    AddOrganizationMemberRequest,
    CreateOrganizationRequest,
    OrganizationMemberResponse,
    OrganizationResponse,
    UpdateOrganizationMemberRoleRequest,
    UpdateOrganizationRequest,
    slugify_name,
)
from app.utils.audit import record_audit_event

router = APIRouter(prefix="/organizations", tags=["organizations"])


def _serialize_org(org: Organization, my_role: OrganizationRole) -> OrganizationResponse:
    return OrganizationResponse(
        id=org.id,
        name=org.name,
        slug=org.slug,
        primary_domain=org.primary_domain,
        google_customer_id=org.google_customer_id,
        edition=org.edition,
        is_active=org.is_active,
        my_role=my_role,
        created_at=org.created_at.isoformat(),
        updated_at=org.updated_at.isoformat(),
    )


def _serialize_member(membership: OrganizationMembership) -> OrganizationMemberResponse:
    return OrganizationMemberResponse(
        id=membership.id,
        organization_id=membership.organization_id,
        user_id=membership.user_id,
        email=membership.user.email,
        full_name=membership.user.full_name,
        role=membership.role,
        is_active=membership.is_active,
        created_at=membership.created_at.isoformat(),
    )


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
def create_organization(
    request: Request,
    payload: CreateOrganizationRequest,
    user: CurrentUser,
    db: Session = Depends(get_db),
):
    slug = payload.slug or slugify_name(payload.name)
    if not slug or len(slug) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Could not derive a valid organization slug",
        )

    if db.query(Organization).filter(Organization.slug == slug).first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An organization with this slug is already registered",
        )

    if (
        payload.primary_domain
        and db.query(Organization).filter(Organization.primary_domain == payload.primary_domain).first() is not None
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An organization with this domain is already registered",
        )

    org = Organization(
        name=payload.name,
        slug=slug,
        primary_domain=payload.primary_domain,
        edition=payload.edition,
        created_by=user.id,
        is_active=True,
    )
    try:
        db.add(org)
        db.flush()
        membership = OrganizationMembership(
            organization_id=org.id,
            user_id=user.id,
            role=OrganizationRole.ORG_ADMIN,
            is_active=True,
        )
        db.add(membership)
        db.commit()
        db.refresh(org)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization slug or domain is already registered",
        ) from exc

    record_audit_event(
        db,
        actor_id=user.id,
        action="org.created",
        resource=org.id,
        details={"organization_id": org.id, "slug": org.slug},
        request=request,
    )
    return _serialize_org(org, OrganizationRole.ORG_ADMIN)


@router.get("", response_model=list[OrganizationResponse])
def list_my_organizations(user: CurrentUser, db: Session = Depends(get_db)):
    memberships = (
        db.query(OrganizationMembership)
        .join(Organization, OrganizationMembership.organization_id == Organization.id)
        .filter(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.is_active.is_(True),
            Organization.is_active.is_(True),
        )
        .options(joinedload(OrganizationMembership.organization))
        .order_by(OrganizationMembership.created_at.desc())
        .all()
    )
    return [_serialize_org(m.organization, m.role) for m in memberships]


@router.get("/{organization_id}", response_model=OrganizationResponse)
def get_organization(membership: OrgMember):
    return _serialize_org(membership.organization, membership.role)


@router.patch("/{organization_id}", response_model=OrganizationResponse)
def update_organization(
    request: Request,
    payload: UpdateOrganizationRequest,
    membership: OrgAdmin,
    db: Session = Depends(get_db),
):
    org = membership.organization
    if payload.name is not None:
        org.name = payload.name
    if payload.edition is not None:
        org.edition = payload.edition
    db.commit()
    db.refresh(org)

    record_audit_event(
        db,
        actor_id=membership.user_id,
        action="org.updated",
        resource=org.id,
        details={"organization_id": org.id},
        request=request,
    )
    return _serialize_org(org, membership.role)


@router.get("/{organization_id}/members", response_model=list[OrganizationMemberResponse])
def list_organization_members(membership: OrgMember, db: Session = Depends(get_db)):
    members = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == membership.organization_id,
            OrganizationMembership.is_active.is_(True),
        )
        .options(joinedload(OrganizationMembership.user))
        .order_by(OrganizationMembership.created_at.asc())
        .all()
    )
    return [_serialize_member(m) for m in members]


@router.post("/{organization_id}/members", response_model=OrganizationMemberResponse, status_code=status.HTTP_201_CREATED)
def add_organization_member(
    request: Request,
    payload: AddOrganizationMemberRequest,
    membership: OrgAdmin,
    db: Session = Depends(get_db),
):
    target_user = db.query(User).filter(User.email == payload.email.lower()).first()
    if target_user is None or not target_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    existing = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == membership.organization_id,
            OrganizationMembership.user_id == target_user.id,
        )
        .first()
    )
    if existing is not None:
        if existing.is_active:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User is already an active member of this organization",
            )
        existing.is_active = True
        existing.role = payload.role
        db.commit()
        db.refresh(existing)
        existing.user = target_user
        record_audit_event(
            db,
            actor_id=membership.user_id,
            action="org.member_added",
            resource=existing.id,
            details={"organization_id": membership.organization_id, "target_user_id": target_user.id, "role": payload.role.value},
            request=request,
        )
        return _serialize_member(existing)

    new_member = OrganizationMembership(
        organization_id=membership.organization_id,
        user_id=target_user.id,
        role=payload.role,
        is_active=True,
    )
    db.add(new_member)
    db.commit()
    db.refresh(new_member)
    new_member.user = target_user

    record_audit_event(
        db,
        actor_id=membership.user_id,
        action="org.member_added",
        resource=new_member.id,
        details={"organization_id": membership.organization_id, "target_user_id": target_user.id, "role": payload.role.value},
        request=request,
    )
    return _serialize_member(new_member)


@router.patch("/{organization_id}/members/{membership_id}", response_model=OrganizationMemberResponse)
def update_member_role(
    membership_id: str,
    request: Request,
    payload: UpdateOrganizationMemberRoleRequest,
    admin_membership: OrgAdmin,
    db: Session = Depends(get_db),
):
    target = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.id == membership_id,
            OrganizationMembership.organization_id == admin_membership.organization_id,
            OrganizationMembership.is_active.is_(True),
        )
        .options(joinedload(OrganizationMembership.user))
        .first()
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Membership not found")

    if target.role == OrganizationRole.ORG_ADMIN and payload.role != OrganizationRole.ORG_ADMIN:
        admin_count = (
            db.query(OrganizationMembership)
            .filter(
                OrganizationMembership.organization_id == admin_membership.organization_id,
                OrganizationMembership.role == OrganizationRole.ORG_ADMIN,
                OrganizationMembership.is_active.is_(True),
            )
            .count()
        )
        if admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote the last organization administrator",
            )

    target.role = payload.role
    db.commit()
    db.refresh(target)

    record_audit_event(
        db,
        actor_id=admin_membership.user_id,
        action="org.member_role_updated",
        resource=target.id,
        details={"organization_id": admin_membership.organization_id, "role": payload.role.value},
        request=request,
    )
    return _serialize_member(target)


@router.delete("/{organization_id}/members/{membership_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_organization_member(
    membership_id: str,
    request: Request,
    admin_membership: OrgAdmin,
    db: Session = Depends(get_db),
):
    target = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.id == membership_id,
            OrganizationMembership.organization_id == admin_membership.organization_id,
            OrganizationMembership.is_active.is_(True),
        )
        .first()
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Membership not found")

    if target.role == OrganizationRole.ORG_ADMIN:
        admin_count = (
            db.query(OrganizationMembership)
            .filter(
                OrganizationMembership.organization_id == admin_membership.organization_id,
                OrganizationMembership.role == OrganizationRole.ORG_ADMIN,
                OrganizationMembership.is_active.is_(True),
            )
            .count()
        )
        if admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the last organization administrator",
            )

    target.is_active = False
    db.commit()

    record_audit_event(
        db,
        actor_id=admin_membership.user_id,
        action="org.member_removed",
        resource=membership_id,
        details={"organization_id": admin_membership.organization_id},
        request=request,
    )
