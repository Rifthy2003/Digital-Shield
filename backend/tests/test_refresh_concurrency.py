"""
Security tests for SEC-06: Concurrent Refresh Token Race Condition & Atomic Rotation.

Verifies:
1. Normal refresh still succeeds.
2. Sequential reuse of a consumed token is rejected.
3. Two concurrent refresh requests using the same token cannot both successfully rotate it.
4. Exactly one successful refresh operation is allowed for a single token.
5. The database ends with a consistent token state.
6. Replay detection and session invalidation remain consistent with SEC-05.
7. Concurrent requests cannot create duplicate valid replacement-token chains.
8. Different sessions can refresh independently.
9. Failed refresh transactions do not leave partially created or inconsistent tokens.
10. Refresh token hashes are still stored securely.
11. Real PostgreSQL database row-level locking (SELECT ... FOR UPDATE) concurrency test.
"""
import concurrent.futures
from datetime import datetime, timedelta
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.core.security import generate_refresh_token, hash_password, hash_token
from app.database import get_db
from app.main import app
from app.models.audit_log import AuditLog
from app.models.user import RefreshToken, User, UserSession


@pytest.fixture
def concurrent_env(db_session):
    """
    Provides a per-request database session factory and TestClient
    allowing concurrent requests in separate threads to simulate real
    multi-process/multi-worker database transactions.
    """
    engine = db_session.get_bind()
    TestSessionMaker = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def per_request_get_db():
        session = TestSessionMaker()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = per_request_get_db
    with TestClient(app) as test_client:
        yield test_client, TestSessionMaker
    app.dependency_overrides.clear()


def _create_user_with_session_and_token(session_maker, email="conc_user@example.com", session_id=None):
    """Helper to create a committed user, session, and refresh token, returning primitive IDs."""
    db = session_maker()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(
                email=email,
                password_hash=hash_password("SecurePassword123!"),
                full_name="Concurrency Tester",
            )
            db.add(user)
            db.commit()

        user_id = str(user.id)
        now = datetime.utcnow()
        if session_id is None:
            session_id = str(uuid.uuid4())

        user_session = UserSession(
            id=session_id,
            user_id=user_id,
            is_active=True,
            device_name="Concurrency-Tester-Device",
            client_type="desktop",
            created_at=now,
            last_active_at=now,
            expires_at=now + timedelta(days=7),
        )
        db.merge(user_session)

        raw_rt, token_hash, expires_at = generate_refresh_token()
        rt = RefreshToken(
            session_id=session_id,
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            revoked=False,
            created_at=now,
        )
        db.add(rt)
        db.commit()
        return user_id, session_id, raw_rt, token_hash
    finally:
        db.close()


def test_normal_refresh_succeeds(concurrent_env):
    """1. Normal refresh still succeeds and returns rotated tokens."""
    client, session_maker = concurrent_env
    user_id, session_id, raw_rt, token_hash = _create_user_with_session_and_token(
        session_maker, email="normal_refresh@example.com"
    )

    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": raw_rt})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["refresh_token"] != raw_rt

    # Verify database state
    db = session_maker()
    try:
        old_record = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        assert old_record.revoked is True

        new_hash = hash_token(data["refresh_token"])
        new_record = db.query(RefreshToken).filter(RefreshToken.token_hash == new_hash).first()
        assert new_record is not None
        assert new_record.revoked is False
        assert new_record.session_id == session_id
    finally:
        db.close()


def test_sequential_reuse_of_consumed_token_is_rejected(concurrent_env):
    """2. Sequential reuse of an already-consumed token is rejected with HTTP 401."""
    client, session_maker = concurrent_env
    user_id, session_id, raw_rt, token_hash = _create_user_with_session_and_token(
        session_maker, email="seq_reuse@example.com"
    )

    # First consumption succeeds
    r1 = client.post("/api/v1/auth/refresh", json={"refresh_token": raw_rt})
    assert r1.status_code == 200

    # Sequential attempt with the consumed token is rejected
    r2 = client.post("/api/v1/auth/refresh", json={"refresh_token": raw_rt})
    assert r2.status_code == 401
    assert r2.json()["detail"] == "Invalid or expired refresh token"


def test_concurrent_refresh_requests_cannot_both_rotate_token(concurrent_env):
    """3. Two concurrent refresh requests using the same token cannot both successfully rotate it."""
    client, session_maker = concurrent_env
    user_id, session_id, raw_rt, token_hash = _create_user_with_session_and_token(
        session_maker, email="concurrent_race@example.com"
    )

    def call_refresh():
        return client.post("/api/v1/auth/refresh", json={"refresh_token": raw_rt})

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(call_refresh)
        f2 = executor.submit(call_refresh)
        r1 = f1.result()
        r2 = f2.result()

    status_codes = sorted([r1.status_code, r2.status_code])
    # Both cannot be 200
    assert status_codes != [200, 200], f"Both concurrent requests succeeded: {status_codes}"


def test_exactly_one_successful_refresh_for_single_token(concurrent_env):
    """4. Exactly one successful refresh operation is allowed for a single token."""
    client, session_maker = concurrent_env
    user_id, session_id, raw_rt, token_hash = _create_user_with_session_and_token(
        session_maker, email="exactly_one@example.com"
    )

    def call_refresh():
        return client.post("/api/v1/auth/refresh", json={"refresh_token": raw_rt})

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(call_refresh)
        f2 = executor.submit(call_refresh)
        r1 = f1.result()
        r2 = f2.result()

    status_codes = sorted([r1.status_code, r2.status_code])
    assert status_codes == [200, 401], f"Expected exactly [200, 401], got {status_codes}"


def test_database_ends_with_consistent_token_state(concurrent_env):
    """5. The database ends with a consistent token state after concurrent requests."""
    client, session_maker = concurrent_env
    sid = "sess-consistent-" + str(uuid.uuid4())[:8]
    user_id, session_id, raw_rt, token_hash = _create_user_with_session_and_token(
        session_maker, email="consistent_state@example.com", session_id=sid
    )

    def call_refresh():
        return client.post("/api/v1/auth/refresh", json={"refresh_token": raw_rt})

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(call_refresh)
        f2 = executor.submit(call_refresh)
        f1.result()
        f2.result()

    db = session_maker()
    try:
        tokens = db.query(RefreshToken).filter(RefreshToken.session_id == sid).all()
        # Exactly 2 tokens: the original consumed token + 1 replacement token
        assert len(tokens) == 2, f"Expected exactly 2 tokens in session family, found {len(tokens)}"

        original = next(t for t in tokens if t.token_hash == token_hash)
        assert original.revoked is True

        replacement = next(t for t in tokens if t.token_hash != token_hash)
        assert replacement.user_id == user_id
        assert replacement.session_id == sid
        assert replacement.expires_at > datetime.utcnow()
    finally:
        db.close()


def test_concurrent_losing_request_triggers_sec05_replay_policy(concurrent_env):
    """
    6. Replay detection and session invalidation remain consistent with SEC-05:
    When the losing concurrent request observes the consumed token, it safely applies
    SEC-05 policy by invalidating the session family and recording an audit event.
    """
    client, session_maker = concurrent_env
    sid = "sess-sec05-" + str(uuid.uuid4())[:8]
    user_id, session_id, raw_rt, token_hash = _create_user_with_session_and_token(
        session_maker, email="sec05_concurrency@example.com", session_id=sid
    )

    def call_refresh():
        return client.post("/api/v1/auth/refresh", json={"refresh_token": raw_rt})

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(call_refresh)
        f2 = executor.submit(call_refresh)
        r1 = f1.result()
        r2 = f2.result()

    # One succeeded, one was rejected as replay
    codes = sorted([r1.status_code, r2.status_code])
    assert codes == [200, 401]

    db = session_maker()
    try:
        # Check audit event was recorded
        audit = db.query(AuditLog).filter(
            AuditLog.action == "security.refresh_token_replayed",
            AuditLog.resource == sid,
        ).first()
        assert audit is not None
        assert audit.actor_id == user_id

        # Check session is deactivated
        sess = db.get(UserSession, sid)
        assert sess.is_active is False

        # All tokens in session family marked revoked
        tokens = db.query(RefreshToken).filter(RefreshToken.session_id == sid).all()
        assert all(t.revoked for t in tokens)
    finally:
        db.close()


def test_concurrent_requests_cannot_create_duplicate_token_chains(concurrent_env):
    """
    7. Concurrent requests cannot create duplicate valid replacement-token chains:
    At no point are two active replacement tokens created from a single parent token.
    """
    client, session_maker = concurrent_env
    sid = "sess-chain-" + str(uuid.uuid4())[:8]
    user_id, session_id, raw_rt, token_hash = _create_user_with_session_and_token(
        session_maker, email="chain_test@example.com", session_id=sid
    )

    def call_refresh():
        return client.post("/api/v1/auth/refresh", json={"refresh_token": raw_rt})

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(call_refresh)
        f2 = executor.submit(call_refresh)
        f1.result()
        f2.result()

    db = session_maker()
    try:
        # Total tokens for this session
        all_tokens = db.query(RefreshToken).filter(RefreshToken.session_id == sid).all()
        # Verify no duplicate children: total tokens should be 2 (original + 1 child)
        assert len(all_tokens) == 2, f"Expected 2 tokens, got {len(all_tokens)}"
    finally:
        db.close()


def test_different_sessions_refresh_independently(concurrent_env):
    """
    8. Different sessions can refresh independently:
    Row-level locking targets only the specific refresh token row, so concurrent
    refresh requests for different sessions do not block or interfere with each other.
    """
    client, session_maker = concurrent_env
    u1_id, s1_id, rt1, h1 = _create_user_with_session_and_token(
        session_maker, email="user1_independent@example.com", session_id="sess-indep-1"
    )
    u2_id, s2_id, rt2, h2 = _create_user_with_session_and_token(
        session_maker, email="user2_independent@example.com", session_id="sess-indep-2"
    )

    def call_r1():
        return client.post("/api/v1/auth/refresh", json={"refresh_token": rt1})

    def call_r2():
        return client.post("/api/v1/auth/refresh", json={"refresh_token": rt2})

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(call_r1)
        f2 = executor.submit(call_r2)
        res1 = f1.result()
        res2 = f2.result()

    # Both independent sessions must succeed with HTTP 200
    assert res1.status_code == 200
    assert res2.status_code == 200

    db = session_maker()
    try:
        sess1 = db.get(UserSession, "sess-indep-1")
        sess2 = db.get(UserSession, "sess-indep-2")
        assert sess1.is_active is True
        assert sess2.is_active is True
    finally:
        db.close()


def test_failed_refresh_transaction_leaves_clean_database_state(concurrent_env, monkeypatch):
    """
    9. Failed refresh transactions do not leave partially created or inconsistent tokens.
    Rollback properly reverses consumption and token insertion.
    """
    client, session_maker = concurrent_env
    sid = "sess-fail-" + str(uuid.uuid4())[:8]
    user_id, session_id, raw_rt, token_hash = _create_user_with_session_and_token(
        session_maker, email="fail_trans@example.com", session_id=sid
    )

    # Monkeypatch generate_refresh_token to raise an exception midway
    def broken_generator():
        raise RuntimeError("Simulated failure during token generation")

    monkeypatch.setattr("app.api.routes.auth.generate_refresh_token", broken_generator)

    # Attempt refresh — should trigger exception & rollback
    try:
        client.post("/api/v1/auth/refresh", json={"refresh_token": raw_rt})
    except RuntimeError:
        pass

    db = session_maker()
    try:
        # Original token must remain unrevoked (transaction rolled back)
        stored = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        assert stored.revoked is False

        # No new tokens inserted
        tokens = db.query(RefreshToken).filter(RefreshToken.session_id == sid).all()
        assert len(tokens) == 1
    finally:
        db.close()


def test_refresh_token_hashes_stored_securely(concurrent_env):
    """
    10. Refresh token hashes are still stored securely:
    All refresh tokens stored in the database are 64-character SHA-256 hashes,
    never plaintext tokens.
    """
    client, session_maker = concurrent_env
    user_id, session_id, raw_rt, token_hash = _create_user_with_session_and_token(
        session_maker, email="hash_secure@example.com"
    )

    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": raw_rt})
    assert resp.status_code == 200
    new_raw = resp.json()["refresh_token"]

    db = session_maker()
    try:
        tokens = db.query(RefreshToken).all()
        assert len(tokens) > 0
        for t in tokens:
            assert len(t.token_hash) == 64
            assert all(c in "0123456789abcdef" for c in t.token_hash.lower())
            assert raw_rt != t.token_hash
            assert new_raw != t.token_hash
    finally:
        db.close()


def test_real_postgresql_concurrent_refresh_if_configured():
    """
    11. Direct test on PostgreSQL:
    When DATABASE_URL is PostgreSQL, verify real database row locks (SELECT ... FOR UPDATE)
    serialize concurrent requests and prevent duplicate rotation across threads.
    """
    from app.config import get_settings
    settings = get_settings()
    if not settings.DATABASE_URL.startswith("postgresql"):
        pytest.skip("PostgreSQL not configured in this environment")

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(settings.DATABASE_URL)
    PgSessionMaker = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def pg_get_db():
        s = PgSessionMaker()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = pg_get_db
    try:
        with TestClient(app) as client:
            user_id, session_id, raw_rt, token_hash = _create_user_with_session_and_token(
                PgSessionMaker, email="pg_concurrency@example.com", session_id="sess-pg-race-" + str(uuid.uuid4())[:8]
            )

            def do_refresh():
                return client.post("/api/v1/auth/refresh", json={"refresh_token": raw_rt})

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                f1 = executor.submit(do_refresh)
                f2 = executor.submit(do_refresh)
                r1 = f1.result()
                r2 = f2.result()

            codes = sorted([r1.status_code, r2.status_code])
            assert codes == [200, 401], f"Expected [200, 401] on PostgreSQL, got {codes}"

            # Check database state
            db = PgSessionMaker()
            try:
                tokens = db.query(RefreshToken).filter(RefreshToken.session_id == session_id).all()
                assert len(tokens) == 2
                assert any(t.token_hash == token_hash and t.revoked is True for t in tokens)
            finally:
                db.close()
    finally:
        app.dependency_overrides.clear()
