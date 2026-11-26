"""
Database & Migration tests for Phase 18 — Task 18.3: OAuth Models & Alembic Migration.

Covers:
1. OAuthState creation and unique state_hash constraint.
2. ConnectedAccount creation and User relationship.
3. Multiple Google accounts linked to a single Infora user.
4. Same Google identity cannot be linked to another Infora user.
5. Different Infora users can connect different Google accounts.
6. OAuthToken relationship, encryption_key_id, encrypted storage, and nullable refresh token.
7. Cascade deletion (ConnectedAccount -> OAuthToken; User -> OAuthState/ConnectedAccount/OAuthToken).
8. Unique constraints on OAuthState, ConnectedAccount, and OAuthToken.
9. Alembic migration upgrade/downgrade verification.
"""
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.exc import IntegrityError

from app.core.crypto import MultiFernetTokenCipher
from app.models import ConnectedAccount, OAuthState, OAuthToken, User


def _enable_sqlite_fk(db_session):
    """Ensure SQLite enforces ON DELETE CASCADE during unit tests."""
    bind = db_session.get_bind()
    if bind.dialect.name == "sqlite":
        db_session.execute(__import__("sqlalchemy").text("PRAGMA foreign_keys=ON"))


def _create_user(db_session, email: str) -> User:
    user = User(email=email, password_hash="argon2_fake_hash", full_name="Test User")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_oauth_state_creation_and_unique_hash(db_session):
    user = _create_user(db_session, "state_user@example.com")
    cipher = MultiFernetTokenCipher(Fernet.generate_key().decode())
    state_hash = hashlib.sha256(b"raw-state-token").hexdigest()
    nonce_hash = hashlib.sha256(b"raw-nonce-token").hexdigest()
    expires = datetime.utcnow() + timedelta(minutes=10)

    oauth_state = OAuthState(
        user_id=user.id,
        provider="google",
        state_hash=state_hash,
        nonce_hash=nonce_hash,
        code_verifier_encrypted=cipher.encrypt("pkce-verifier-xyz"),
        redirect_uri="http://localhost:5174/oauth/google/callback",
        expires_at=expires,
    )
    db_session.add(oauth_state)
    db_session.commit()
    db_session.refresh(oauth_state)

    assert oauth_state.id is not None
    assert oauth_state.used is False
    assert oauth_state.state_hash == state_hash
    assert cipher.decrypt(oauth_state.code_verifier_encrypted) == "pkce-verifier-xyz"
    assert len(user.oauth_states) == 1

    # Duplicate state_hash must be rejected
    dup_state = OAuthState(
        user_id=user.id,
        provider="google",
        state_hash=state_hash,
        nonce_hash=nonce_hash,
        code_verifier_encrypted=cipher.encrypt("another-verifier"),
        redirect_uri="http://localhost:5174/oauth/google/callback",
        expires_at=expires,
    )
    db_session.add(dup_state)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_multiple_google_accounts_for_single_infora_user(db_session):
    user = _create_user(db_session, "multi_google@example.com")

    acc1 = ConnectedAccount(
        user_id=user.id,
        provider="google",
        provider_user_id="google-sub-1001",
        provider_email="personal@gmail.com",
        provider_email_verified=True,
        display_name="Personal Gmail",
        scopes="openid email profile",
    )
    acc2 = ConnectedAccount(
        user_id=user.id,
        provider="google",
        provider_user_id="google-sub-1002",
        provider_email="work@gmail.com",
        provider_email_verified=True,
        display_name="Work Gmail",
        scopes="openid email profile",
    )
    db_session.add_all([acc1, acc2])
    db_session.commit()
    db_session.refresh(user)

    assert len(user.connected_accounts) == 2
    emails = {a.provider_email for a in user.connected_accounts}
    assert emails == {"personal@gmail.com", "work@gmail.com"}


def test_same_google_identity_cannot_belong_to_another_user(db_session):
    user_a = _create_user(db_session, "user_a@example.com")
    user_b = _create_user(db_session, "user_b@example.com")

    acc_a = ConnectedAccount(
        user_id=user_a.id,
        provider="google",
        provider_user_id="google-sub-shared",
        provider_email="shared@gmail.com",
        scopes="openid email profile",
    )
    db_session.add(acc_a)
    db_session.commit()

    acc_b = ConnectedAccount(
        user_id=user_b.id,
        provider="google",
        provider_user_id="google-sub-shared",
        provider_email="shared@gmail.com",
        scopes="openid email profile",
    )
    db_session.add(acc_b)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_different_users_can_connect_different_google_accounts(db_session):
    user_a = _create_user(db_session, "alpha@example.com")
    user_b = _create_user(db_session, "beta@example.com")

    db_session.add_all([
        ConnectedAccount(
            user_id=user_a.id,
            provider="google",
            provider_user_id="google-sub-alpha",
            provider_email="alpha@gmail.com",
            scopes="openid email profile",
        ),
        ConnectedAccount(
            user_id=user_b.id,
            provider="google",
            provider_user_id="google-sub-beta",
            provider_email="beta@gmail.com",
            scopes="openid email profile",
        ),
    ])
    db_session.commit()

    assert db_session.query(ConnectedAccount).count() == 2


def test_oauth_token_relationship_encryption_key_id_and_unique_account(db_session):
    user = _create_user(db_session, "token_user@example.com")
    cipher = MultiFernetTokenCipher(Fernet.generate_key().decode())

    account = ConnectedAccount(
        user_id=user.id,
        provider="google",
        provider_user_id="google-sub-tok",
        provider_email="tok@gmail.com",
        scopes="openid email profile",
    )
    db_session.add(account)
    db_session.commit()

    token = OAuthToken(
        connected_account_id=account.id,
        access_token_encrypted=cipher.encrypt("ya29.access"),
        refresh_token_encrypted=None,  # Nullable when provider omits refresh token
        encryption_key_id=cipher.key_id,
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    db_session.add(token)
    db_session.commit()
    db_session.refresh(account)

    assert account.token is not None
    assert account.token.encryption_key_id == cipher.key_id
    assert account.token.refresh_token_encrypted is None
    assert cipher.decrypt(account.token.access_token_encrypted) == "ya29.access"

    # Unique connected_account_id constraint prevents multiple token rows per account
    dup_token = OAuthToken(
        connected_account_id=account.id,
        access_token_encrypted=cipher.encrypt("ya29.access-2"),
        encryption_key_id=cipher.key_id,
    )
    db_session.add(dup_token)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_cascade_deletion_for_oauth_records(db_session):
    _enable_sqlite_fk(db_session)
    user = _create_user(db_session, "cascade_oauth@example.com")
    cipher = MultiFernetTokenCipher(Fernet.generate_key().decode())

    state = OAuthState(
        user_id=user.id,
        provider="google",
        state_hash=hashlib.sha256(b"s1").hexdigest(),
        code_verifier_encrypted=cipher.encrypt("v1"),
        redirect_uri="http://localhost:5174/oauth/google/callback",
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    acc1 = ConnectedAccount(
        user_id=user.id,
        provider="google",
        provider_user_id="sub-c1",
        scopes="openid email",
    )
    acc2 = ConnectedAccount(
        user_id=user.id,
        provider="google",
        provider_user_id="sub-c2",
        scopes="openid email",
    )
    db_session.add_all([state, acc1, acc2])
    db_session.commit()

    tok1 = OAuthToken(
        connected_account_id=acc1.id,
        access_token_encrypted=cipher.encrypt("at1"),
        encryption_key_id=cipher.key_id,
    )
    tok2 = OAuthToken(
        connected_account_id=acc2.id,
        access_token_encrypted=cipher.encrypt("at2"),
        encryption_key_id=cipher.key_id,
    )
    db_session.add_all([tok1, tok2])
    db_session.commit()

    # Deleting one ConnectedAccount cascades to its OAuthToken only
    db_session.delete(acc1)
    db_session.commit()
    assert db_session.query(ConnectedAccount).count() == 1
    assert db_session.query(OAuthToken).count() == 1

    # Deleting User cascades to remaining OAuthState, ConnectedAccount, and OAuthToken
    db_session.delete(user)
    db_session.commit()
    assert db_session.query(OAuthState).count() == 0
    assert db_session.query(ConnectedAccount).count() == 0
    assert db_session.query(OAuthToken).count() == 0


def test_alembic_migration_upgrade_and_downgrade(tmp_path, monkeypatch):
    db_file = tmp_path / "alembic_oauth_test.db"
    db_url = f"sqlite:///{db_file}"

    backend_dir = Path(__file__).resolve().parents[1]
    alembic_cfg = Config(str(backend_dir / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)

    monkeypatch.setenv("DATABASE_URL", db_url)
    from app.config import get_settings
    get_settings.cache_clear()

    try:
        # Create pre-existing base tables (existing f18487bc8773 migration uses ALTER FK
        # which SQLite doesn't support without batch mode) and stamp at f18487bc8773.
        engine = create_engine(db_url)
        from app.database import Base
        Base.metadata.create_all(
            bind=engine,
            tables=[
                t
                for name, t in Base.metadata.tables.items()
                if name not in {"oauth_states", "connected_accounts", "oauth_tokens", "organizations", "organization_memberships"}
            ],
        )
        command.stamp(alembic_cfg, "f18487bc8773")

        # Upgrade to head (runs a7c3e9d14b2f_add_oauth_models)
        command.upgrade(alembic_cfg, "head")
        tables_after_upgrade = set(inspect(engine).get_table_names())
        assert {"users", "user_sessions", "oauth_states", "connected_accounts", "oauth_tokens"}.issubset(
            tables_after_upgrade
        )

        # Downgrade to f18487bc8773 removes only the OAuth tables
        command.downgrade(alembic_cfg, "f18487bc8773")
        tables_after_downgrade = set(inspect(engine).get_table_names())
        assert "oauth_states" not in tables_after_downgrade
        assert "connected_accounts" not in tables_after_downgrade
        assert "oauth_tokens" not in tables_after_downgrade
        assert {"users", "user_sessions"}.issubset(tables_after_downgrade)
        engine.dispose()
    finally:
        get_settings.cache_clear()
