import os
import tempfile

os.environ.setdefault("DATABASE_URL", f"sqlite:///{tempfile.gettempdir()}/cybersentinel_test.db")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.db_models  # noqa: F401  ensure models are registered on Base
from app.db import Base, get_db
from app.main import app


@pytest.fixture()
def db_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture()
def client(db_session):
    def _get_db_override():
        yield db_session

    app.dependency_overrides[get_db] = _get_db_override
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def register_and_login(client):
    def _do(email: str, password: str = "TestPass123!") -> str:
        client.post("/auth/register", json={"email": email, "password": password})
        response = client.post("/auth/login", json={"email": email, "password": password})
        return response.json()["access_token"]

    return _do


@pytest.fixture()
def admin_headers(register_and_login):
    # the first account ever registered in a fresh db is auto-promoted to admin
    token = register_and_login("admin@example.com")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def analyst_headers(client, admin_headers, register_and_login):
    token = register_and_login("analyst@example.com")
    users = client.get("/users", headers=admin_headers).json()
    user_id = next(u["id"] for u in users if u["email"] == "analyst@example.com")
    client.patch(f"/users/{user_id}/role", json={"role": "analyst"}, headers=admin_headers)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def viewer_headers(admin_headers, register_and_login):
    # depends on admin_headers purely to guarantee admin@example.com registers
    # first, so this account doesn't accidentally get auto-promoted to admin.
    token = register_and_login("viewer@example.com")
    return {"Authorization": f"Bearer {token}"}
