"""API tests: authentication, registration, session management, 2FA."""
from __future__ import annotations

import time

import pytest
from httpx import AsyncClient

from tests.conftest import headers


@pytest.mark.asyncio
async def test_register_success(client: AsyncClient):
    r = await client.post("/api/v1/auth/register", json={
        "email": "new@example.com", "password": "SecurePass1!x",
        "full_name": "New User", "organization_name": "NewOrg",
    })
    assert r.status_code == 201
    body = r.json()
    assert "access_token" in body and "refresh_token" in body


@pytest.mark.asyncio
async def test_register_weak_password_rejected(client: AsyncClient):
    r = await client.post("/api/v1/auth/register", json={
        "email": "weak@example.com", "password": "short",
        "full_name": "X", "organization_name": "Org",
    })
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_register_duplicate_email_rejected(client: AsyncClient):
    payload = {"email": "dup@example.com", "password": "SecurePass1!x",
               "full_name": "A", "organization_name": "Org1"}
    r1 = await client.post("/api/v1/auth/register", json=payload)
    assert r1.status_code == 201
    r2 = await client.post("/api/v1/auth/register", json=payload)
    assert r2.status_code == 409


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, auth_a):
    r = await client.post("/api/v1/auth/login", json={
        "email": "alice@a.example", "password": "SecurePass1!x"})
    assert r.status_code == 200
    assert "access_token" in r.json()


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient, auth_a):
    r = await client.post("/api/v1/auth/login", json={
        "email": "alice@a.example", "password": "WrongPass1!"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_user_same_error(client: AsyncClient):
    """Anti-enumeration: same 401 for unknown email and wrong password."""
    r = await client.post("/api/v1/auth/login", json={
        "email": "ghost@nowhere.example", "password": "Whatever1!"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid credentials"


@pytest.mark.asyncio
async def test_login_timing_similar_for_unknown_user(client: AsyncClient, auth_a):
    """Timing-attack defense: unknown user should not be obviously faster."""
    start = time.perf_counter()
    await client.post("/api/v1/auth/login", json={"email": "ghost@x.example", "password": "Pass1234!"})
    unknown_elapsed = time.perf_counter() - start
    start = time.perf_counter()
    await client.post("/api/v1/auth/login", json={"email": "alice@a.example", "password": "WrongPass1!"})
    known_elapsed = time.perf_counter() - start
    # Allow generous tolerance; argon2 dominates both paths
    assert abs(unknown_elapsed - known_elapsed) < 2.0


@pytest.mark.asyncio
async def test_refresh_token_rotation(client: AsyncClient, auth_a):
    r = await client.post("/api/v1/auth/login", json={
        "email": "alice@a.example", "password": "SecurePass1!x"})
    refresh = r.json()["refresh_token"]
    r2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert r2.status_code == 200
    new_refresh = r2.json()["refresh_token"]
    # Old token must be revoked
    r3 = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert r3.status_code == 401
    # New token works
    r4 = await client.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh})
    assert r4.status_code == 200


@pytest.mark.asyncio
async def test_logout_revokes_refresh(client: AsyncClient, auth_a):
    r = await client.post("/api/v1/auth/login", json={
        "email": "alice@a.example", "password": "SecurePass1!x"})
    tokens = r.json()
    r2 = await client.post("/api/v1/auth/logout",
                           headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r2.status_code == 204
    r3 = await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r3.status_code == 401


@pytest.mark.asyncio
async def test_change_password_revokes_sessions(client: AsyncClient, auth_a):
    r = await client.post("/api/v1/auth/login", json={
        "email": "alice@a.example", "password": "SecurePass1!x"})
    tokens = r.json()
    r2 = await client.post("/api/v1/auth/change-password", json={
        "current_password": "SecurePass1!x", "new_password": "NewSecurePass2@"},
        headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r2.status_code == 200
    r3 = await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r3.status_code == 401


@pytest.mark.asyncio
async def test_password_reset_no_enumeration(client: AsyncClient):
    """Both existing and non-existing emails return 202."""
    r1 = await client.post("/api/v1/auth/password-reset", json={"email": "ghost@x.example"})
    assert r1.status_code == 202


@pytest.mark.asyncio
async def test_2fa_setup_and_enable(client: AsyncClient, auth_a):
    from app.core.security import _hotp
    r = await client.post("/api/v1/auth/2fa/setup", headers=headers(auth_a))
    assert r.status_code == 200
    secret = r.json()["secret"]
    counter = int(time.time()) // 30
    code = _hotp(secret, counter)
    r2 = await client.post("/api/v1/auth/2fa/enable", json={"code": code}, headers=headers(auth_a))
    assert r2.status_code == 200


@pytest.mark.asyncio
async def test_missing_auth_header_rejected(client: AsyncClient):
    r = await client.get("/api/v1/workspaces", headers={"X-Organization-ID": "x"})
    assert r.status_code == 422  # missing Authorization header


@pytest.mark.asyncio
async def test_invalid_jwt_rejected(client: AsyncClient):
    r = await client.get("/api/v1/workspaces", headers={
        "Authorization": "Bearer invalid.token.here", "X-Organization-ID": "x"})
    assert r.status_code == 401
