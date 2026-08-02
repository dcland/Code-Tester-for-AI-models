"""Shared pytest fixtures.

Each test gets an isolated in-memory database and a fresh app/container, so
tests are hermetic and can run in parallel without cross-contamination.
"""

from __future__ import annotations

import base64
import os
import tempfile

import pytest
import pytest_asyncio

# Deterministic test secrets BEFORE importing settings (env-only, no plaintext
# secrets in code). A fixed 32-byte KEK keeps envelope encryption reproducible.
os.environ.setdefault("VAULTNOTE_ENVIRONMENT", "test")
os.environ.setdefault("VAULTNOTE_JWT_SECRET", "test-jwt-secret-value")
os.environ.setdefault("VAULTNOTE_PASSWORD_PEPPER", "test-pepper-value")
os.environ.setdefault(
    "VAULTNOTE_MASTER_KEK",
    base64.urlsafe_b64encode(b"0" * 32).decode(),
)
os.environ.setdefault("VAULTNOTE_ANALYTICS_PSEUDONYM_SALT", "test-salt")
# Speed up Argon2 in tests (still Argon2id, just lighter parameters).
os.environ.setdefault("VAULTNOTE_ARGON2_TIME_COST", "1")
os.environ.setdefault("VAULTNOTE_ARGON2_MEMORY_COST", "8192")

import httpx  # noqa: E402
from httpx import ASGITransport  # noqa: E402

from app.core.config import Settings  # noqa: E402
from app.core.container import Container  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest_asyncio.fixture
async def container() -> Container:
    tmpdir = tempfile.mkdtemp(prefix="vaultnote-test-")
    settings = Settings(
        environment="test",
        database_url="sqlite+aiosqlite:///:memory:",
        storage_dir=os.path.join(tmpdir, "storage"),
    )
    c = Container(settings)
    await c.startup()
    yield c
    await c.shutdown()


@pytest_asyncio.fixture
async def app(container: Container):
    return create_app(container)


@pytest_asyncio.fixture
async def client(app) -> httpx.AsyncClient:
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport,
                                 base_url="http://testserver") as ac:
        yield ac


class UserSession:
    """Convenience wrapper carrying a registered user's tokens and org."""

    def __init__(self, client: httpx.AsyncClient, data: dict, org_id: str,
                 user_id: str, email: str, password: str) -> None:
        self._client = client
        self.access_token = data["access_token"]
        self.refresh_token = data["refresh_token"]
        self.org_id = org_id
        self.user_id = user_id
        self.email = email
        self.password = password

    @property
    def auth(self) -> dict:
        return {"Authorization": f"Bearer {self.access_token}"}


@pytest_asyncio.fixture
async def register_user(client: httpx.AsyncClient):
    async def _register(email: str, password: str = "Sup3rSecret!pw",
                        org: str = "Acme Inc") -> UserSession:
        resp = await client.post("/api/v1/auth/register", json={
            "email": email, "password": password,
            "display_name": "Test User", "organization_name": org,
        })
        assert resp.status_code == 201, resp.text
        data = resp.json()
        orgs = await client.get("/api/v1/me/organizations",
                                headers={"Authorization": f"Bearer {data['access_token']}"})
        org_id = orgs.json()[0]["id"]
        # Decode user id from the JWT sub (no secret needed to read the claim).
        import jwt
        sub = jwt.decode(data["access_token"], options={"verify_signature": False})["sub"]
        return UserSession(client, data, org_id, sub, email, password)

    return _register
