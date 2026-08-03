import os
import tempfile

# A fresh, unique directory per test session - never a fixed shared path.
# A fixed path would accumulate schema state across unrelated test runs
# (bit us once already: a leftover file from before migrations existed had
# tables but no alembic_version row, so migrations tried to CREATE TABLE
# into a DB that already had them). This is only used for the app's
# lifespan startup migration; actual test requests go through the
# db_session fixture's own per-test database instead.
os.environ.setdefault("DATABASE_URL", f"sqlite:///{tempfile.mkdtemp()}/cybersentinel_test.db")
# `.delay()` runs the Celery task inline instead of needing a real
# broker/worker - must be set before app.celery_app is imported (by
# app.main -> app.tasks) since it's read once at module load time.
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "true")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.db_models  # noqa: F401  ensure models are registered on Base
from app import tasks
from app.db import get_db, run_migrations
from app.main import app
from app.rate_limit import limiter

# Off by default for the suite as a whole: most tests log in/register far
# more than the real per-minute limits allow, all from the same TestClient
# "IP". test_rate_limiting.py flips this on for its own tests specifically
# to prove the real 429 behavior, then restores it.
limiter.enabled = False


@pytest.fixture()
def db_session(tmp_path):
    db_path = tmp_path / "test.db"
    run_migrations(f"sqlite:///{db_path}")
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture()
def org_id(db_session) -> int:
    """A bare organization row for tests that exercise app/ingestion.py,
    app/rag.py, app/correlation.py etc directly against db_session, below
    the HTTP layer - organization_id is NOT NULL everywhere now, and these
    tests have no `client`/JWT context to derive one from the way the
    request-driven tests do via `user.organization_id`."""
    from app.db_models import Organization

    org = Organization(name="Test Org", slug="test-org")
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)
    return org.id


@pytest.fixture()
def client(db_session):
    def _get_db_override():
        yield db_session

    app.dependency_overrides[get_db] = _get_db_override

    # The Celery task (eager mode) needs its own db session bound to the
    # same underlying sqlite file as db_session, not the real module-level
    # SessionLocal - which in tests is bound to an unrelated throwaway db
    # (the DATABASE_URL set above, only used for the app's lifespan
    # startup migration). A fresh session per call, same engine/file, so
    # commits made by the task are visible through db_session afterwards,
    # matching how a real separate worker process would interact with the
    # same database.
    task_engine = db_session.get_bind()
    task_sessionmaker = sessionmaker(bind=task_engine)
    tasks.set_session_factory(task_sessionmaker)

    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    tasks.reset_session_factory()


@pytest.fixture()
def register_and_login(client):
    """Joins an *existing* organization (POST /auth/register now always
    requires an organization_slug - see test_org below for creating one)."""

    def _do(email: str, organization_slug: str, password: str = "TestPass123!") -> str:
        client.post(
            "/auth/register",
            json={"email": email, "password": password, "organization_slug": organization_slug},
        )
        response = client.post("/auth/login", json={"email": email, "password": password})
        return response.json()["access_token"]

    return _do


@pytest.fixture()
def test_org(client):
    """Creates one organization with a fixed admin account (POST
    /organizations - the "sign up a new company" flow, replacing the old
    single-tenant "first user ever registered becomes admin" behavior).
    Every other role fixture below joins *this same* organization, since
    RBAC tests need multiple users in one tenant to be meaningful; a
    separate `other_org_*` fixture exists for actual cross-tenant isolation
    tests."""
    response = client.post(
        "/organizations",
        json={"organization_name": "Test Org", "email": "admin@example.com", "password": "TestPass123!"},
    )
    org_slug = response.json()["organization_slug"]
    login = client.post("/auth/login", json={"email": "admin@example.com", "password": "TestPass123!"})
    token = login.json()["access_token"]
    return org_slug, {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin_headers(test_org):
    return test_org[1]


@pytest.fixture()
def analyst_headers(client, test_org, register_and_login):
    org_slug, admin = test_org
    token = register_and_login("analyst@example.com", org_slug)
    users = client.get("/users", headers=admin).json()
    user_id = next(u["id"] for u in users if u["email"] == "analyst@example.com")
    client.patch(f"/users/{user_id}/role", json={"role": "analyst"}, headers=admin)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def viewer_headers(test_org, register_and_login):
    org_slug, _admin = test_org
    token = register_and_login("viewer@example.com", org_slug)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def other_org_admin_headers(client):
    """A completely separate organization/tenant, for cross-tenant
    isolation tests (org A must never see/touch org B's data)."""
    response = client.post(
        "/organizations",
        json={"organization_name": "Other Org", "email": "other-admin@example.com", "password": "TestPass123!"},
    )
    login = client.post("/auth/login", json={"email": "other-admin@example.com", "password": "TestPass123!"})
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
