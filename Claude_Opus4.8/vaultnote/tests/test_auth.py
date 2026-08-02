"""Authentication, session, and account-security tests."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio

STRONG = "Sup3rSecret!pw"


async def test_register_and_login(client, register_user):
    user = await register_user("alice@example.com")
    resp = await client.post("/api/v1/auth/login",
                             json={"email": "alice@example.com", "password": STRONG})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


async def test_login_wrong_password_rejected(client, register_user):
    await register_user("bob@example.com")
    resp = await client.post("/api/v1/auth/login",
                             json={"email": "bob@example.com", "password": "wrongwrong123!"})
    assert resp.status_code == 401
    # Generic error — no account detail leaked.
    assert resp.json()["error"]["code"] == "authentication_failed"


async def test_login_unknown_user_same_error(client):
    resp = await client.post("/api/v1/auth/login",
                             json={"email": "ghost@example.com", "password": STRONG})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "authentication_failed"


async def test_weak_password_rejected(client):
    resp = await client.post("/api/v1/auth/register", json={
        "email": "weak@example.com", "password": "short",
        "display_name": "x", "organization_name": "Org",
    })
    assert resp.status_code == 422


async def test_account_lockout_after_repeated_failures(client, register_user):
    await register_user("lock@example.com")
    for _ in range(5):
        await client.post("/api/v1/auth/login",
                          json={"email": "lock@example.com", "password": "badpassword1!"})
    # Even the correct password is now temporarily locked out.
    resp = await client.post("/api/v1/auth/login",
                             json={"email": "lock@example.com", "password": STRONG})
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "account_locked"


async def test_refresh_rotation_invalidates_old_token(client, register_user):
    user = await register_user("rot@example.com")
    r1 = await client.post("/api/v1/auth/refresh",
                           json={"refresh_token": user.refresh_token})
    assert r1.status_code == 200
    # Reusing the original (now rotated) refresh token must fail.
    r2 = await client.post("/api/v1/auth/refresh",
                           json={"refresh_token": user.refresh_token})
    assert r2.status_code == 401


async def test_logout_all_revokes_access_token(client, register_user):
    user = await register_user("all@example.com")
    resp = await client.post("/api/v1/auth/logout-all", headers=user.auth)
    assert resp.status_code == 204
    # The previously valid access token is now rejected immediately.
    after = await client.get("/api/v1/me/organizations", headers=user.auth)
    assert after.status_code == 401


async def test_password_change_invalidates_sessions(client, register_user):
    user = await register_user("chg@example.com")
    resp = await client.post("/api/v1/auth/password/change", headers=user.auth, json={
        "current_password": STRONG, "new_password": "Br4ndNew!pass",
    })
    assert resp.status_code == 204
    after = await client.get("/api/v1/me/organizations", headers=user.auth)
    assert after.status_code == 401
    # New password works.
    login = await client.post("/api/v1/auth/login",
                              json={"email": "chg@example.com", "password": "Br4ndNew!pass"})
    assert login.status_code == 200


async def test_password_reset_flow(client, register_user):
    await register_user("reset@example.com")
    req = await client.post("/api/v1/auth/password/reset-request",
                            json={"email": "reset@example.com"})
    assert req.status_code == 202
    token = req.json()["debug_reset_token"]  # exposed only in non-prod
    confirm = await client.post("/api/v1/auth/password/reset-confirm",
                                json={"token": token, "new_password": "Res3tted!pass"})
    assert confirm.status_code == 204
    login = await client.post("/api/v1/auth/login",
                              json={"email": "reset@example.com", "password": "Res3tted!pass"})
    assert login.status_code == 200


async def test_password_reset_request_hides_unknown_account(client):
    req = await client.post("/api/v1/auth/password/reset-request",
                            json={"email": "nobody@example.com"})
    assert req.status_code == 202
    assert "debug_reset_token" not in req.json()  # no token => no enumeration


async def test_totp_enroll_and_enforced_on_login(client, register_user):
    import time

    from app.core.security import SecurityService

    user = await register_user("totp@example.com")
    enroll = await client.post("/api/v1/auth/2fa/enroll", headers=user.auth)
    assert enroll.status_code == 200
    secret = enroll.json()["secret"]

    code = SecurityService._hotp(secret, int(time.time()) // 30)
    confirm = await client.post("/api/v1/auth/2fa/confirm", headers=user.auth,
                                json={"code": code})
    assert confirm.status_code == 204

    # Login without a code is now rejected with a 2FA challenge.
    no_code = await client.post("/api/v1/auth/login",
                                json={"email": "totp@example.com", "password": STRONG})
    assert no_code.status_code == 401
    assert no_code.json()["error"]["code"] == "two_factor_required"

    # Login with a valid code succeeds.
    code2 = SecurityService._hotp(secret, int(time.time()) // 30)
    ok = await client.post("/api/v1/auth/login", json={
        "email": "totp@example.com", "password": STRONG, "totp_code": code2,
    })
    assert ok.status_code == 200


async def test_security_headers_present(client):
    resp = await client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in resp.headers
    assert "X-Request-ID" in resp.headers
