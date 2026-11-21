import os
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///./_test.db")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-not-for-production")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.core.rate_limit import limiter
from app.main import app

TEST_DB_PATH = Path(__file__).resolve().parent / "_test.db"


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """
    The rate limiter keeps in-memory state keyed by client IP, which is
    constant across TestClient requests. Without a reset, tests run later in
    the suite would trip limits meant to catch real abuse, not test traffic.
    """
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture(scope="function")
def db_session():
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
    engine = create_engine(f"sqlite:///{TEST_DB_PATH}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
        if TEST_DB_PATH.exists():
            TEST_DB_PATH.unlink()


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def registered_user(client):
    payload = {"email": "test.user@example.com", "password": "CorrectHorse123Battery", "full_name": "Test User"}
    resp = client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    return payload


@pytest.fixture
def auth_headers(client, registered_user):
    resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
