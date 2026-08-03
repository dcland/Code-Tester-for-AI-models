"""Tests: GDPR/CCPA compliance, audit log integrity, PII redaction, billing, analytics."""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.core.compliance import AuditLog
from tests.conftest import headers


async def _setup(client: AsyncClient, auth: dict) -> tuple[str, str]:
    r = await client.post("/api/v1/workspaces", json={"name": "WS"}, headers=headers(auth))
    ws = r.json()["id"]
    r2 = await client.post(f"/api/v1/workspaces/{ws}/notes",
                           json={"title": "T", "content": "C"}, headers=headers(auth))
    return ws, r2.json()["id"]


# ---- GDPR Art. 15 - Data Export ----------------------------------------------

@pytest.mark.asyncio
async def test_data_export(client: AsyncClient, auth_a):
    await _setup(client, auth_a)
    r = await client.get("/api/v1/admin/export", headers=headers(auth_a))
    assert r.status_code == 200
    data = r.json()
    assert data["user"]["email"] == "alice@a.example"
    assert "memberships" in data and "consents" in data


@pytest.mark.asyncio
async def test_data_export_zip(client: AsyncClient, auth_a):
    r = await client.get("/api/v1/admin/export/zip", headers=headers(auth_a))
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    assert len(r.content) > 50


# ---- GDPR Art. 17 - Erasure ---------------------------------------------------

@pytest.mark.asyncio
async def test_user_erasure(client: AsyncClient, auth_a):
    await _setup(client, auth_a)
    r = await client.delete("/api/v1/admin/users/me", headers=headers(auth_a))
    assert r.status_code == 200
    assert r.json()["erased"] is True
    # User can no longer log in
    r2 = await client.post("/api/v1/auth/login", json={
        "email": "alice@a.example", "password": "SecurePass1!x"})
    assert r2.status_code == 401


@pytest.mark.asyncio
async def test_organization_erasure(client: AsyncClient, auth_a):
    await _setup(client, auth_a)
    r = await client.delete("/api/v1/admin/organization", headers=headers(auth_a))
    assert r.status_code == 200
    assert r.json()["erased"] is True


# ---- GDPR Art. 7 - Consent -----------------------------------------------------

@pytest.mark.asyncio
async def test_consent_record_and_list(client: AsyncClient, auth_a):
    r = await client.post("/api/v1/admin/consent",
                          json={"purpose": "analytics", "granted": True},
                          headers=headers(auth_a))
    assert r.status_code == 201
    r2 = await client.get("/api/v1/admin/consent", headers=headers(auth_a))
    assert len(r2.json()) == 1
    assert r2.json()[0]["purpose"] == "analytics"


# ---- Audit log -----------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_log_records_actions(client: AsyncClient, auth_a):
    await _setup(client, auth_a)
    r = await client.get("/api/v1/admin/audit", headers=headers(auth_a))
    assert r.status_code == 200
    actions = [e["action"] for e in r.json()]
    assert "note_created" in actions


@pytest.mark.asyncio
async def test_audit_log_contains_no_pii(client: AsyncClient, auth_a):
    """Audit entries must not contain raw user IDs or emails."""
    await _setup(client, auth_a)
    r = await client.get("/api/v1/admin/audit", headers=headers(auth_a))
    for event in r.json():
        assert "alice@a.example" not in str(event)
        assert auth_a["user_id"] not in str(event)


@pytest.mark.asyncio
async def test_audit_chain_integrity(client: AsyncClient, auth_a):
    await _setup(client, auth_a)
    assert AuditLog.verify_chain() is True


@pytest.mark.asyncio
async def test_audit_tampering_detected(client: AsyncClient, auth_a):
    await _setup(client, auth_a)
    # Tamper with an event
    if AuditLog._events:
        AuditLog._events[0]["action"] = "tampered"
        assert AuditLog.verify_chain() is False


# ---- Retention purge -----------------------------------------------------------

@pytest.mark.asyncio
async def test_retention_purge_endpoint(client: AsyncClient, auth_a):
    r = await client.post("/api/v1/admin/retention/purge", headers=headers(auth_a))
    assert r.status_code == 200
    assert "purged_notes" in r.json()


# ---- Billing -------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_subscription(client: AsyncClient, auth_a):
    r = await client.get("/api/v1/billing/subscription", headers=headers(auth_a))
    assert r.status_code == 200
    assert r.json()["plan"] == "free"


@pytest.mark.asyncio
async def test_plan_change_generates_invoice(client: AsyncClient, auth_a):
    r = await client.post("/api/v1/billing/plan",
                          json={"plan": "pro", "payment_token": "tok_visa_4242"},
                          headers=headers(auth_a))
    assert r.status_code == 200
    assert r.json()["plan"] == "pro"
    r2 = await client.get("/api/v1/billing/invoices", headers=headers(auth_a))
    assert len(r2.json()) == 1


@pytest.mark.asyncio
async def test_proration_applied(client: AsyncClient, auth_a):
    # Upgrade to pro, then to business - proration credit should reduce amount
    await client.post("/api/v1/billing/plan", json={"plan": "pro"}, headers=headers(auth_a))
    r = await client.post("/api/v1/billing/plan", json={"plan": "business"}, headers=headers(auth_a))
    body = r.json()
    assert body["proration_credit_cents"] >= 0
    assert body["amount_due_cents"] <= 3600


# ---- Analytics (differential privacy) -----------------------------------------

@pytest.mark.asyncio
async def test_analytics_dashboard(client: AsyncClient, auth_a):
    await _setup(client, auth_a)
    r = await client.get("/api/v1/analytics/dashboard", headers=headers(auth_a))
    assert r.status_code == 200
    data = r.json()
    assert "active_members" in data and "total_notes" in data
    assert data["epsilon"] > 0
    # Counts are non-negative after DP clamping
    assert data["total_notes"] >= 0


@pytest.mark.asyncio
async def test_analytics_no_individual_data(client: AsyncClient, auth_a):
    """Dashboard must not expose per-user information."""
    r = await client.get("/api/v1/analytics/dashboard", headers=headers(auth_a))
    body = str(r.json())
    assert auth_a["user_id"] not in body
    assert "alice" not in body.lower()


# ---- Security headers -----------------------------------------------------------

@pytest.mark.asyncio
async def test_security_headers_present(client: AsyncClient):
    r = await client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Strict-Transport-Security" in r.headers
    assert "Content-Security-Policy" in r.headers


@pytest.mark.asyncio
async def test_request_id_header(client: AsyncClient):
    r = await client.get("/health")
    assert "X-Request-ID" in r.headers
