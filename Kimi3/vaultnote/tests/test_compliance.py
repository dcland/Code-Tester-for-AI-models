"""Tests: GDPR/CCPA compliance, durable audit log integrity, PII redaction,
retention plan-scoping, billing, analytics."""
from __future__ import annotations

import io
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update

from app.core.compliance import AuditLog
from app.models.entities import AuditEventRecord, FileAsset, Note, Subscription
from tests.conftest import headers

_PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x00IEND\xaeB`\x82")


async def _setup(client: AsyncClient, auth: dict) -> tuple[str, str]:
    r = await client.post("/api/v1/workspaces", json={"name": "WS"}, headers=headers(auth))
    ws = r.json()["id"]
    r2 = await client.post(f"/api/v1/workspaces/{ws}/notes",
                           json={"title": "T", "content": "C"}, headers=headers(auth))
    return ws, r2.json()["id"]


async def _upload_png(client: AsyncClient, auth: dict, ws: str, name: str = "f.png") -> str:
    r = await client.post(f"/api/v1/workspaces/{ws}/files", content=_PNG,
                          headers={**headers(auth), "Content-Type": "image/png",
                                   "X-File-Name": name})
    assert r.status_code == 201
    return r.json()["id"]


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
async def test_data_export_zip_contains_files(client: AsyncClient, auth_a):
    """The ZIP export must include the user's encrypted files, not only JSON."""
    ws, _ = await _setup(client, auth_a)
    await _upload_png(client, auth_a, ws)
    r = await client.get("/api/v1/admin/export/zip", headers=headers(auth_a))
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert "user_data.json" in names
    assert any(n.startswith("files/") and n.endswith(".enc") for n in names)


# ---- GDPR Art. 17 - Erasure ---------------------------------------------------

@pytest.mark.asyncio
async def test_user_erasure(client: AsyncClient, auth_a):
    await _setup(client, auth_a)
    r = await client.delete("/api/v1/admin/users/me", headers=headers(auth_a))
    assert r.status_code == 200
    assert r.json()["erased"] is True
    r2 = await client.post("/api/v1/auth/login", json={
        "email": "alice@a.example", "password": "SecurePass1!x"})
    assert r2.status_code == 401


@pytest.mark.asyncio
async def test_user_erasure_removes_file_blobs(client: AsyncClient, auth_a, db_session):
    """Art. 17: erasure deletes the physical encrypted blobs, not only rows."""
    ws, _ = await _setup(client, auth_a)
    await _upload_png(client, auth_a, ws)
    asset = (await db_session.execute(select(FileAsset))).scalar_one()
    blob = Path(asset.storage_path)
    assert blob.exists()

    r = await client.delete("/api/v1/admin/users/me", headers=headers(auth_a))
    assert r.status_code == 200
    assert not blob.exists()


@pytest.mark.asyncio
async def test_organization_erasure_removes_blobs(client: AsyncClient, auth_a, db_session):
    ws, _ = await _setup(client, auth_a)
    await _upload_png(client, auth_a, ws)
    asset = (await db_session.execute(select(FileAsset))).scalar_one()
    blob = Path(asset.storage_path)
    assert blob.exists()

    r = await client.delete("/api/v1/admin/organization", headers=headers(auth_a))
    assert r.status_code == 200
    assert r.json()["erased"] is True
    assert not blob.exists()


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


# ---- Durable, signed audit log --------------------------------------------------

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
async def test_audit_chain_integrity(client: AsyncClient, auth_a, db_session):
    await _setup(client, auth_a)
    assert await AuditLog.verify_chain(db_session) is True


@pytest.mark.asyncio
async def test_audit_tampering_detected(client: AsyncClient, auth_a, db_session):
    """Modifying a persisted audit row invalidates the HMAC chain."""
    await _setup(client, auth_a)
    rows = (await db_session.execute(
        select(AuditEventRecord).order_by(AuditEventRecord.seq))).scalars().all()
    assert rows, "expected durable audit rows"
    await db_session.execute(
        update(AuditEventRecord)
        .where(AuditEventRecord.seq == rows[0].seq)
        .values(action="tampered"))
    await db_session.commit()
    assert await AuditLog.verify_chain(db_session) is False


@pytest.mark.asyncio
async def test_audit_verify_endpoint(client: AsyncClient, auth_a):
    await _setup(client, auth_a)
    r = await client.get("/api/v1/admin/audit/verify", headers=headers(auth_a))
    assert r.status_code == 200
    assert r.json()["valid"] is True


# ---- Retention purge: plan-aware and tenant-scoped ----------------------------

async def _soft_delete_note_old(db_session, note_id: str, days: int) -> None:
    await db_session.execute(
        update(Note).where(Note.id == note_id)
        .values(deleted_at=datetime.now(UTC) - timedelta(days=days)))
    await db_session.commit()


@pytest.mark.asyncio
async def test_retention_purge_free_plan(client: AsyncClient, auth_a, db_session):
    """Free tier (30d): a note soft-deleted 31 days ago is purged."""
    _, note_id = await _setup(client, auth_a)
    await _soft_delete_note_old(db_session, note_id, days=31)
    r = await client.post("/api/v1/admin/retention/purge", headers=headers(auth_a))
    assert r.status_code == 200
    assert r.json()["purged_notes"] == 1
    assert r.json()["plan"] == "free"


@pytest.mark.asyncio
async def test_retention_purge_respects_paid_plan(client: AsyncClient, auth_a, db_session):
    """A paid tenant's data must NOT be purged with the 30-day free window -
    the exact defect the benchmark flagged (unused plan filter)."""
    _, note_id = await _setup(client, auth_a)
    # Upgrade this tenant to a paid plan
    await db_session.execute(
        update(Subscription).where(Subscription.organization_id == auth_a["org_id"])
        .values(plan="pro"))
    await _soft_delete_note_old(db_session, note_id, days=31)  # > free window, < paid window
    r = await client.post("/api/v1/admin/retention/purge", headers=headers(auth_a))
    assert r.status_code == 200
    assert r.json()["purged_notes"] == 0  # paid 365-day window protects it
    assert r.json()["plan"] == "pro"


@pytest.mark.asyncio
async def test_retention_purge_is_tenant_scoped(client: AsyncClient, auth_a, auth_b, db_session):
    """A purge triggered by Org A must never touch Org B's data."""
    _, note_a = await _setup(client, auth_a)
    _, note_b = await _setup(client, auth_b)
    await _soft_delete_note_old(db_session, note_a, days=31)
    await _soft_delete_note_old(db_session, note_b, days=31)
    r = await client.post("/api/v1/admin/retention/purge", headers=headers(auth_a))
    assert r.json()["purged_notes"] == 1
    remaining = (await db_session.execute(
        select(Note).where(Note.id == note_b))).scalar_one_or_none()
    assert remaining is not None  # Org B's note untouched


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
