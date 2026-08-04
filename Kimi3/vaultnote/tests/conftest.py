"""
Pytest fixtures: in-memory DB, test client, authenticated users.
"""
from __future__ import annotations

import os
import tempfile

# Use in-memory SQLite for tests and fixed secrets for determinism
os.environ["VAULTNOTE_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["VAULTNOTE_JWT_SECRET_KEY"] = "test-secret-key-for-jwt-signing-32bytes!"
os.environ["VAULTNOTE_PASSWORD_PEPPER"] = "test-pepper-32-bytes-long-enough!!"
os.environ["VAULTNOTE_MASTER_ENCRYPTION_KEY"] = "test-master-key-32-bytes-long!!!"
os.environ["VAULTNOTE_PSEUDONYM_SALT"] = "test-pseudonym-salt-32-bytes!!!!!"
os.environ["VAULTNOTE_AUDIT_HMAC_KEY"] = "test-audit-hmac-key-32-bytes!!!!!"
os.environ["VAULTNOTE_RATE_LIMIT_DEFAULT"] = "10000"
os.environ["VAULTNOTE_RATE_LIMIT_AUTH"] = "10000"
os.environ["VAULTNOTE_FILE_STORAGE_PATH"] = tempfile.mkdtemp(prefix="vaultnote-test-files-")

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.main import app
from app.models.database import Base, get_db
from app.models.entities import Membership, Role
from app.utils.mailer import outbox

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
    outbox.clear()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


async def _register_and_login(client: AsyncClient, db_session: AsyncSession,
                              email: str, org_name: str) -> dict:
    """Register a fresh user (owner of their own new org) and log in."""
    from app.services.auth_service import AuthService
    svc = AuthService(db_session)
    user, org = await svc.register(email, "SecurePass1!x", "Test User", org_name)
    await db_session.commit()
    r = await client.post("/api/v1/auth/login", json={"email": email, "password": "SecurePass1!x"})
    token = r.json()["access_token"]
    return {"token": token, "org_id": org.id, "user_id": user.id}


async def _add_org_member(client: AsyncClient, db_session: AsyncSession,
                          email: str, org_id: str, role: Role) -> dict:
    """Create a user and grant them ``role`` in an EXISTING organization."""
    auth = await _register_and_login(client, db_session, email, f"{email.split('@')[0]}-org")
    db_session.add(Membership(user_id=auth["user_id"], organization_id=org_id, role=role))
    await db_session.commit()
    # Point the returned context at the shared org, not the user's own org.
    return {"token": auth["token"], "org_id": org_id, "user_id": auth["user_id"]}


@pytest_asyncio.fixture
async def auth_a(client: AsyncClient, db_session: AsyncSession) -> dict:
    """Authenticated OWNER of Org A."""
    return await _register_and_login(client, db_session, "alice@a.example", "Org A")


@pytest_asyncio.fixture
async def auth_b(client: AsyncClient, db_session: AsyncSession) -> dict:
    """Authenticated OWNER of Org B (separate tenant, NOT a member of Org A)."""
    return await _register_and_login(client, db_session, "bob@b.example", "Org B")


@pytest_asyncio.fixture
async def member_a(client: AsyncClient, db_session: AsyncSession, auth_a: dict) -> dict:
    """A MEMBER-role user inside Org A."""
    return await _add_org_member(client, db_session, "carol@a.example", auth_a["org_id"], Role.MEMBER)


@pytest_asyncio.fixture
async def viewer_a(client: AsyncClient, db_session: AsyncSession, auth_a: dict) -> dict:
    """A VIEWER-role user inside Org A (read-only ceiling)."""
    return await _add_org_member(client, db_session, "dave@a.example", auth_a["org_id"], Role.VIEWER)


def headers(auth: dict) -> dict:
    return {"Authorization": f"Bearer {auth['token']}", "X-Organization-ID": auth["org_id"]}
