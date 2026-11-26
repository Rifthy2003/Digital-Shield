"""
Security & Integration tests for Phase 19 — Task 19.1: Organization & Membership Foundation.

Covers:
1. Organization creation and domain uniqueness/validation.
2. Membership creation and UNIQUE(organization_id, user_id) constraint.
3. org_admin authorization & last-admin protection.
4. org_viewer restrictions (403 on management operations).
5. Unauthenticated requests (401).
6. Cross-tenant access attempts (404).
7. Cross-organization membership IDOR protection.
8. Unauthorized role escalation prevention.
9. Personal OAuth account isolation from org_admin.
"""
import pytest
from sqlalchemy.exc import IntegrityError

from app.models.oauth import ConnectedAccount
from app.models.organization import Organization, OrganizationMembership, OrganizationRole


def _register_and_login(client, email: str, password: str = "CorrectHorse123Battery") -> dict[str, str]:
    reg = client.post("/api/v1/auth/register", json={"email": email, "password": password, "full_name": email})
    assert reg.status_code == 201
    login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_unauthenticated_organization_requests_rejected(client):
    assert client.post("/api/v1/organizations", json={"name": "Acme", "primary_domain": "acme.com"}).status_code == 401
    assert client.get("/api/v1/organizations").status_code == 401
    assert client.get("/api/v1/organizations/org-1").status_code == 401
    assert client.patch("/api/v1/organizations/org-1", json={"name": "New"}).status_code == 401
    assert client.get("/api/v1/organizations/org-1/members").status_code == 401
    assert client.post("/api/v1/organizations/org-1/members", json={"email": "a@b.com"}).status_code == 401
    assert client.patch("/api/v1/organizations/org-1/members/m-1", json={"role": "org_admin"}).status_code == 401
    assert client.delete("/api/v1/organizations/org-1/members/m-1").status_code == 401


def test_organization_creation_and_domain_uniqueness(client, auth_headers):
    # Invalid domain rejected
    bad = client.post(
        "/api/v1/organizations",
        json={"name": "Bad Org", "primary_domain": "not a domain!"},
        headers=auth_headers,
    )
    assert bad.status_code == 422

    # Valid creation assigns creator as org_admin and auto-generates slug
    created = client.post(
        "/api/v1/organizations",
        json={"name": "Acme Corp", "primary_domain": "ACME.COM", "edition": "Workspace Business Plus"},
        headers=auth_headers,
    )
    assert created.status_code == 201
    org = created.json()
    assert org["slug"] == "acme-corp"
    assert org["primary_domain"] == "acme.com"
    assert org["my_role"] == "org_admin"
    assert org["is_active"] is True

    # Duplicate slug rejected (409)
    dup_slug = client.post(
        "/api/v1/organizations",
        json={"name": "Acme Corp", "slug": "acme-corp"},
        headers=auth_headers,
    )
    assert dup_slug.status_code == 409

    # Duplicate domain rejected (409)
    dup = client.post(
        "/api/v1/organizations",
        json={"name": "Acme Clone", "slug": "acme-clone", "primary_domain": "acme.com"},
        headers=auth_headers,
    )
    assert dup.status_code == 409


def test_membership_rbac_viewer_restrictions_and_role_escalation(client):
    admin_headers = _register_and_login(client, "org_admin@acme.com")
    viewer_headers = _register_and_login(client, "org_viewer@acme.com")

    org = client.post(
        "/api/v1/organizations",
        json={"name": "Acme Sec", "primary_domain": "acmesec.com"},
        headers=admin_headers,
    ).json()
    org_id = org["id"]

    # Admin adds viewer
    add_res = client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "org_viewer@acme.com", "role": "org_viewer"},
        headers=admin_headers,
    )
    assert add_res.status_code == 201
    viewer_membership_id = add_res.json()["id"]

    # Duplicate membership rejected
    assert client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "org_viewer@acme.com", "role": "org_viewer"},
        headers=admin_headers,
    ).status_code == 409

    # Viewer can read organization & members
    assert client.get(f"/api/v1/organizations/{org_id}", headers=viewer_headers).status_code == 200
    assert len(client.get(f"/api/v1/organizations/{org_id}/members", headers=viewer_headers).json()) == 2

    # Viewer CANNOT update org, add members, escalate own role, or remove members (403)
    assert client.patch(f"/api/v1/organizations/{org_id}", json={"name": "Hacked"}, headers=viewer_headers).status_code == 403
    assert client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "someone@acme.com", "role": "org_admin"},
        headers=viewer_headers,
    ).status_code == 403
    assert client.patch(
        f"/api/v1/organizations/{org_id}/members/{viewer_membership_id}",
        json={"role": "org_admin"},
        headers=viewer_headers,
    ).status_code == 403
    assert client.delete(
        f"/api/v1/organizations/{org_id}/members/{viewer_membership_id}",
        headers=viewer_headers,
    ).status_code == 403

    # Admin can update org, promote/demote viewer, and cannot demote/remove last admin
    assert client.patch(f"/api/v1/organizations/{org_id}", json={"name": "Acme Security"}, headers=admin_headers).status_code == 200

    members = client.get(f"/api/v1/organizations/{org_id}/members", headers=admin_headers).json()
    admin_membership_id = next(m["id"] for m in members if m["role"] == "org_admin")

    assert client.patch(
        f"/api/v1/organizations/{org_id}/members/{admin_membership_id}",
        json={"role": "org_viewer"},
        headers=admin_headers,
    ).status_code == 400
    assert client.delete(
        f"/api/v1/organizations/{org_id}/members/{admin_membership_id}",
        headers=admin_headers,
    ).status_code == 400

    # Admin can remove viewer (deactivates membership) and inactive member is denied
    assert client.delete(f"/api/v1/organizations/{org_id}/members/{viewer_membership_id}", headers=admin_headers).status_code == 204
    assert client.get(f"/api/v1/organizations/{org_id}", headers=viewer_headers).status_code == 404
    assert client.get(f"/api/v1/organizations/{org_id}/members", headers=viewer_headers).status_code == 404
    assert client.get("/api/v1/organizations", headers=viewer_headers).json() == []


def test_inactive_organization_and_inactive_membership_denied(client, db_session):
    admin_headers = _register_and_login(client, "inact_admin@acme.com")
    org = client.post(
        "/api/v1/organizations",
        json={"name": "Inactive Test", "slug": "inactive-test"},
        headers=admin_headers,
    ).json()
    org_id = org["id"]

    db_org = db_session.get(Organization, org_id)
    db_org.is_active = False
    db_session.commit()

    assert client.get(f"/api/v1/organizations/{org_id}", headers=admin_headers).status_code == 404
    assert client.get("/api/v1/organizations", headers=admin_headers).json() == []


def test_cross_tenant_isolation_and_membership_idor_protection(client):
    alice_headers = _register_and_login(client, "alice@tenant-a.com")
    bob_headers = _register_and_login(client, "bob@tenant-b.com")

    org_a = client.post(
        "/api/v1/organizations",
        json={"name": "Tenant A", "primary_domain": "tenant-a.com"},
        headers=alice_headers,
    ).json()
    org_b = client.post(
        "/api/v1/organizations",
        json={"name": "Tenant B", "primary_domain": "tenant-b.com"},
        headers=bob_headers,
    ).json()

    bob_members = client.get(f"/api/v1/organizations/{org_b['id']}/members", headers=bob_headers).json()
    bob_membership_id = bob_members[0]["id"]

    # Bob only sees Tenant B in /organizations
    assert [o["id"] for o in client.get("/api/v1/organizations", headers=bob_headers).json()] == [org_b["id"]]

    # Bob cannot access Tenant A at all (404 prevents tenant enumeration)
    assert client.get(f"/api/v1/organizations/{org_a['id']}", headers=bob_headers).status_code == 404
    assert client.patch(f"/api/v1/organizations/{org_a['id']}", json={"name": "X"}, headers=bob_headers).status_code == 404
    assert client.get(f"/api/v1/organizations/{org_a['id']}/members", headers=bob_headers).status_code == 404
    assert client.post(
        f"/api/v1/organizations/{org_a['id']}/members",
        json={"email": "bob@tenant-b.com", "role": "org_admin"},
        headers=bob_headers,
    ).status_code == 404

    # Alice (admin of Tenant A) cannot mutate Bob's membership ID via Tenant A's route (IDOR -> 404)
    assert client.patch(
        f"/api/v1/organizations/{org_a['id']}/members/{bob_membership_id}",
        json={"role": "org_viewer"},
        headers=alice_headers,
    ).status_code == 404
    assert client.delete(
        f"/api/v1/organizations/{org_a['id']}/members/{bob_membership_id}",
        headers=alice_headers,
    ).status_code == 404


def test_personal_oauth_accounts_remain_isolated_from_org_admin(client, db_session):
    admin_headers = _register_and_login(client, "admin@org-iso.com")
    member_headers = _register_and_login(client, "member@org-iso.com")

    org = client.post(
        "/api/v1/organizations",
        json={"name": "Org Isolation", "primary_domain": "org-iso.com"},
        headers=admin_headers,
    ).json()
    client.post(
        f"/api/v1/organizations/{org['id']}/members",
        json={"email": "member@org-iso.com", "role": "org_viewer"},
        headers=admin_headers,
    )

    # Member has a personal Google ConnectedAccount
    member_me = client.get("/api/v1/auth/me", headers=member_headers).json()
    db_session.add(
        ConnectedAccount(
            user_id=member_me["id"],
            provider="google",
            provider_user_id="personal-sub-private-1",
            provider_email="member.personal@gmail.com",
            scopes="openid email profile",
        )
    )
    db_session.commit()

    # Org admin's /oauth/accounts and /organizations/{id}/members never expose member's personal Google account
    admin_oauth = client.get("/api/v1/oauth/accounts", headers=admin_headers)
    assert admin_oauth.status_code == 200
    assert admin_oauth.json() == []

    members_resp = client.get(f"/api/v1/organizations/{org['id']}/members", headers=admin_headers)
    assert "member.personal@gmail.com" not in members_resp.text
    assert "personal-sub-private-1" not in members_resp.text


def test_db_unique_membership_constraint(db_session):
    from app.models.user import User

    u = User(email="db_uniq@example.com", password_hash="hash", full_name="U")
    org = Organization(name="DB Org", slug="db-org", primary_domain="dbuniq.com")
    db_session.add_all([u, org])
    db_session.commit()

    db_session.add(OrganizationMembership(organization_id=org.id, user_id=u.id, role=OrganizationRole.ORG_ADMIN))
    db_session.commit()

    db_session.add(OrganizationMembership(organization_id=org.id, user_id=u.id, role=OrganizationRole.ORG_VIEWER))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
