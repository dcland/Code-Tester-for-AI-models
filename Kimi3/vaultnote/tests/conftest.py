"""
Pytest fixtures: in-memory DB, test client, authenticated users.
"""
from __future__ import annotations

import os

# Use in-memory SQLite for tests and fixed secrets for determinism
os.environ["VAULTNOTE_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["VAULTNOTE_JWT_SECRET_KEY"] = "test-secret-key-for-jwt-signing-32bytes!"
os.environ["VAULTNOTE_PASSWORD_PEPPER"] = "test-pepper-32-bytes-long-enough!!"
os.environ["VAULTNOTE_MASTER_ENCRYPTION_KEY"] = "test-master-key-32-bytes-long!!!"
os.environ["VAULTNOTE_RATE_LIMIT_DEFAULT"] = "10000"
os.environ["VAULTNOTE_RATE_LIMIT_AUTH"] = "10000"

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.main import app
from app.models.database import Base, get_db
from app.core.compliance import AuditLog

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def db_engine():
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_engine):
    factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db
    AuditLog.reset()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


async def _register_and_login(client: AsyncClient, email: str, org_name: str) -> tuple[str, str, str]:
    """Register a user+org and return (access_token, org_id, user_id)."""
    r = await client.post("/api/v1/auth/register", json={
        "email": email, "password": "SecurePass1!x",
        "full_name": "Test User", "organization_name": org_name,
    })
    assert r.status_code == 201, r.text
    data = r.json()
    token = data["access_token"]
    # Extract user id from token
    from app.core.security import decode_token
    user_id = decode_token(token)["sub"]
    # Get org id via membership lookup - create a workspace to learn org
    r2 = await client.post("/api/v1/workspaces", json={"name": "ws"},
                           headers={"Authorization": f"Bearer {token}", "X-Organization-ID": "x"})
    # We need org id differently - query from DB instead
    return token, "", user_id


@pytest_asyncio.fixture
async def auth_a(client: AsyncClient, db_session: AsyncSession) -> dict:
    """Authenticated user in Org A with org id resolved."""
    from app.services.auth_service import AuthService
    svc = AuthService(db_session)
    user, org = await svc.register("alice@a.example", "SecurePass1!x", "Alice", "Org A")
    await db_session.commit()
    r = await client.post("/api/v1/auth/login", json={"email": "alice@a.example", "password": "SecurePass1!x"})
    token = r.json()["access_token"]
    return {"token": token, "org_id": org.id, "user_id": user.id}


@pytest_asyncio.fixture
async def auth_b(client: AsyncClient, db_session: AsyncSession) -> dict:
    """Authenticated user in Org B (separate tenant)."""
    from app.services.auth_service import AuthService
    svc = AuthService(db_session)
    user, org = await svc.register("bob@b.example", "SecurePass1!x", "Bob", "Org B")
    await db_session.commit()
    r = await client.post("/api/v1/auth/login", json={"email": "bob@b.example", "password": "SecurePass1!x"})
    token = r.json()["access_token"]
    return {"token": token, "org_id": org.id, "user_id": user.id}


def headers(auth: dict) -> dict:
    return {"Authorization": f"Bearer {auth['token']}", "X-Organization-ID": auth["org_id"]}
