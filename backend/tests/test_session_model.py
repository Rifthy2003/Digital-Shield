from datetime import datetime, timedelta
import pytest
from app.models.user import User, UserSession, RefreshToken, UserRole


def test_user_session_creation(db_session):
    user = User(
        email="session_user@example.com",
        password_hash="argon2_fake_hash",
        full_name="Session Test User",
        role=UserRole.CITIZEN,
    )
    db_session.add(user)
    db_session.commit()

    now = datetime.utcnow()
    expires = now + timedelta(days=7)
    session = UserSession(
        user_id=user.id,
        device_name="Chrome on Windows 11",
        client_type="web",
        user_agent="Mozilla/5.0 Windows NT 10.0",
        ip_address="192.168.1.100",
        expires_at=expires,
    )
    db_session.add(session)
    db_session.commit()
    db_session.refresh(session)

    assert session.id is not None
    assert session.user_id == user.id
    assert session.device_name == "Chrome on Windows 11"
    assert session.client_type == "web"
    assert session.user_agent == "Mozilla/5.0 Windows NT 10.0"
    assert session.ip_address == "192.168.1.100"
    assert session.is_active is True
    assert session.created_at is not None
    assert session.last_active_at is not None
    assert session.expires_at == expires


def test_user_session_relationships(db_session):
    user = User(
        email="multi_session@example.com",
        password_hash="argon2_fake_hash",
        full_name="Multi Session User",
    )
    db_session.add(user)
    db_session.commit()

    now = datetime.utcnow()
    s1 = UserSession(
        user_id=user.id,
        device_name="Desktop Web",
        client_type="web",
        expires_at=now + timedelta(days=7),
    )
    s2 = UserSession(
        user_id=user.id,
        device_name="Mobile iOS",
        client_type="mobile",
        expires_at=now + timedelta(days=30),
    )
    db_session.add_all([s1, s2])
    db_session.commit()
    db_session.refresh(user)

    assert len(user.sessions) == 2
    assert s1.user.email == user.email
    assert s2.user.email == user.email


def test_session_refresh_token_relationship(db_session):
    user = User(
        email="token_user@example.com",
        password_hash="argon2_fake_hash",
    )
    db_session.add(user)
    db_session.commit()

    now = datetime.utcnow()
    session = UserSession(
        user_id=user.id,
        device_name="Firefox Linux",
        expires_at=now + timedelta(days=7),
    )
    db_session.add(session)
    db_session.commit()

    token = RefreshToken(
        session_id=session.id,
        user_id=user.id,
        token_hash="sha256_hash_1",
        expires_at=now + timedelta(days=7),
    )
    db_session.add(token)
    db_session.commit()
    db_session.refresh(session)
    db_session.refresh(token)

    assert len(session.refresh_tokens) == 1
    assert session.refresh_tokens[0].token_hash == "sha256_hash_1"
    assert token.session.id == session.id


def test_multiple_refresh_tokens_per_session(db_session):
    # Simulates rotation within a single session
    user = User(
        email="rotation_user@example.com",
        password_hash="argon2_fake_hash",
    )
    db_session.add(user)
    db_session.commit()

    now = datetime.utcnow()
    session = UserSession(
        user_id=user.id,
        device_name="Chrome Android",
        client_type="mobile",
        expires_at=now + timedelta(days=14),
    )
    db_session.add(session)
    db_session.commit()

    # Initial token
    t1 = RefreshToken(
        session_id=session.id,
        user_id=user.id,
        token_hash="hash_rotated_1",
        expires_at=now + timedelta(days=7),
        revoked=True,
    )
    # First rotation token
    t2 = RefreshToken(
        session_id=session.id,
        user_id=user.id,
        token_hash="hash_rotated_2",
        expires_at=now + timedelta(days=7),
        revoked=True,
    )
    # Current active token
    t3 = RefreshToken(
        session_id=session.id,
        user_id=user.id,
        token_hash="hash_rotated_3",
        expires_at=now + timedelta(days=7),
        revoked=False,
    )
    db_session.add_all([t1, t2, t3])
    db_session.commit()
    db_session.refresh(session)

    assert len(session.refresh_tokens) == 3
    active_tokens = [t for t in session.refresh_tokens if not t.revoked]
    assert len(active_tokens) == 1
    assert active_tokens[0].token_hash == "hash_rotated_3"


def test_session_cascade_delete_tokens(db_session):
    user = User(
        email="cascade_session_user@example.com",
        password_hash="argon2_fake_hash",
    )
    db_session.add(user)
    db_session.commit()

    now = datetime.utcnow()
    session = UserSession(
        user_id=user.id,
        device_name="Test Device",
        expires_at=now + timedelta(days=7),
    )
    db_session.add(session)
    db_session.commit()

    token = RefreshToken(
        session_id=session.id,
        user_id=user.id,
        token_hash="cascade_token_hash",
        expires_at=now + timedelta(days=7),
    )
    db_session.add(token)
    db_session.commit()

    token_id = token.id
    session_id = session.id

    # Delete session
    db_session.delete(session)
    db_session.commit()

    # Verify session is deleted
    assert db_session.get(UserSession, session_id) is None
    # Verify child refresh token is cascade deleted
    assert db_session.get(RefreshToken, token_id) is None
    # Verify parent user still exists
    assert db_session.get(User, user.id) is not None


def test_user_cascade_delete_sessions_and_tokens(db_session):
    user = User(
        email="cascade_all_user@example.com",
        password_hash="argon2_fake_hash",
    )
    db_session.add(user)
    db_session.commit()

    now = datetime.utcnow()
    session = UserSession(
        user_id=user.id,
        device_name="Device To Delete",
        expires_at=now + timedelta(days=7),
    )
    db_session.add(session)
    db_session.commit()

    token = RefreshToken(
        session_id=session.id,
        user_id=user.id,
        token_hash="cascade_all_token_hash",
        expires_at=now + timedelta(days=7),
    )
    db_session.add(token)
    db_session.commit()

    user_id = user.id
    session_id = session.id
    token_id = token.id

    # Delete user
    db_session.delete(user)
    db_session.commit()

    # All should be cascade deleted
    assert db_session.get(User, user_id) is None
    assert db_session.get(UserSession, session_id) is None
    assert db_session.get(RefreshToken, token_id) is None


def test_legacy_refresh_token_without_session_compatible(db_session):
    # Existing refresh tokens with session_id=None must continue to work without errors
    user = User(
        email="legacy_user@example.com",
        password_hash="argon2_fake_hash",
    )
    db_session.add(user)
    db_session.commit()

    now = datetime.utcnow()
    legacy_token = RefreshToken(
        session_id=None,
        user_id=user.id,
        token_hash="legacy_hash_without_session",
        expires_at=now + timedelta(days=7),
        revoked=False,
    )
    db_session.add(legacy_token)
    db_session.commit()
    db_session.refresh(legacy_token)

    assert legacy_token.session_id is None
    assert legacy_token.session is None
    assert legacy_token.user.id == user.id
    assert len(user.refresh_tokens) == 1
    assert len(user.sessions) == 0
