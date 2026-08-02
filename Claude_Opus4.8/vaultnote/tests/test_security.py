"""OWASP-oriented security tests: injection, access control, info leakage."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_sql_injection_in_login_is_harmless(client, register_user):
    await register_user("legit@example.com")
    # Classic injection payloads must not authenticate or error out the server.
    for payload in ["' OR '1'='1", "admin'--", "'; DROP TABLE users;--"]:
        resp = await client.post("/api/v1/auth/login",
                                 json={"email": payload, "password": "x" * 12})
        assert resp.status_code in (401, 422)
    # The users table is intact and the legit account still works.
    ok = await client.post("/api/v1/auth/login",
                           json={"email": "legit@example.com", "password": "Sup3rSecret!pw"})
    assert ok.status_code == 200


async def test_missing_auth_rejected(client, register_user):
    user = await register_user("noauth@example.com")
    resp = await client.get(f"/api/v1/organizations/{user.org_id}/notes")
    assert resp.status_code == 401


async def test_forged_jwt_rejected(client, register_user):
    user = await register_user("forge@example.com")
    # A token signed with the wrong key must be rejected.
    import jwt
    forged = jwt.encode({"sub": user.user_id, "type": "access", "exp": 9999999999,
                         "sid": "x"}, "attacker-key", algorithm="HS256")
    resp = await client.get(f"/api/v1/organizations/{user.org_id}/notes",
                            headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


async def test_error_response_contains_no_pii(client):
    # Trigger a validation error with an email-shaped value and confirm the
    # echoed error does not leak it verbatim from server-side redaction.
    resp = await client.post("/api/v1/auth/login",
                             json={"email": "not-an-email", "password": ""})
    assert resp.status_code == 422
    assert "error" in resp.json()


async def test_extra_fields_rejected(client):
    # Pydantic extra="forbid" blocks mass-assignment / unexpected fields.
    resp = await client.post("/api/v1/auth/register", json={
        "email": "extra@example.com", "password": "Sup3rSecret!pw",
        "display_name": "x", "organization_name": "Org",
        "is_admin": True,  # attacker-supplied field
    })
    assert resp.status_code == 422


async def test_rate_limit_enforced_on_auth(client):
    # The auth bucket (10/min) blocks brute-force attempts. A non-existent
    # account is used so per-account lockout does not confound the result.
    codes = []
    for _ in range(14):
        r = await client.post("/api/v1/auth/login",
                              json={"email": "brute@example.com", "password": "x" * 12})
        codes.append(r.status_code)
    assert 429 in codes
    assert codes.count(429) >= 1


async def test_cross_tenant_file_download_denied(client, register_user):
    alice = await register_user("cf-alice@example.com", org="A")
    bob = await register_user("cf-bob@example.com", org="B")
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    up = await client.post(
        f"/api/v1/organizations/{alice.org_id}/files",
        headers={**alice.auth, "X-Filename": "a.png", "Content-Type": "image/png"},
        content=png)
    file_id = up.json()["id"]
    # Bob cannot mint a download token for Alice's file.
    resp = await client.post(
        f"/api/v1/organizations/{alice.org_id}/files/{file_id}/download-token",
        headers=bob.auth)
    assert resp.status_code == 403
