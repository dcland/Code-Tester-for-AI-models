"""GDPR/CCPA compliance tests: export, erasure, retention, consent, audit."""

from __future__ import annotations

import io
import json
import zipfile

import pytest
from sqlalchemy import func, select

from app.models.audit import AuditLog
from app.models.content import Note
from app.models.user import User

pytestmark = pytest.mark.asyncio


async def test_data_export_is_machine_readable_zip(client, register_user):
    user = await register_user("exp@example.com")
    await client.post(f"/api/v1/organizations/{user.org_id}/notes",
                      headers=user.auth,
                      json={"title": "Exported", "body": "my data"})
    resp = await client.get("/api/v1/me/export", headers=user.auth)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    manifest = json.loads(zf.read("data.json"))
    assert manifest["schema"] == "vaultnote.export/v1"
    assert manifest["account"]["email"] == "exp@example.com"
    titles = [n["title"] for org in manifest["organizations"] for n in org["notes"]]
    assert "Exported" in titles


async def test_right_to_erasure_cascades(container, client, register_user):
    user = await register_user("erase@example.com")
    await client.post(f"/api/v1/organizations/{user.org_id}/notes",
                      headers=user.auth, json={"title": "t", "body": "b"})

    resp = await client.delete("/api/v1/me", headers=user.auth)
    assert resp.status_code == 204

    async with container.database.session_factory() as session:
        # User row is gone.
        assert (await session.get(User, user.user_id)) is None
        # Their notes are gone (cascade); org (sole member) is erased too.
        note_count = (await session.execute(
            select(func.count()).select_from(Note).where(
                Note.org_id == user.org_id))).scalar_one()
        assert note_count == 0


async def test_erasure_keeps_pii_free_audit_trail(container, client, register_user):
    user = await register_user("audit-erase@example.com")
    await client.delete("/api/v1/me", headers=user.auth)
    async with container.database.session_factory() as session:
        rows = (await session.execute(select(AuditLog))).scalars().all()
        # Audit entries survive but never contain the email or any PII.
        blob = json.dumps([{
            "a": r.action, "actor": r.actor_pseudonym, "ctx": r.context,
        } for r in rows])
        assert "audit-erase@example.com" not in blob
        assert any(r.action == "privacy.user.erased" for r in rows)


async def test_audit_log_never_contains_pii(container, client, register_user):
    user = await register_user("pii@example.com")
    await client.post(f"/api/v1/organizations/{user.org_id}/notes",
                      headers=user.auth,
                      json={"title": "MY SENSITIVE TITLE", "body": "secret"})
    audit = await client.get(
        f"/api/v1/organizations/{user.org_id}/audit", headers=user.auth)
    assert audit.status_code == 200
    text = json.dumps(audit.json())
    assert "MY SENSITIVE TITLE" not in text
    assert "pii@example.com" not in text


async def test_audit_chain_is_tamper_evident(container, client, register_user):
    user = await register_user("chain@example.com")
    for i in range(3):
        await client.post(f"/api/v1/organizations/{user.org_id}/notes",
                          headers=user.auth, json={"title": f"n{i}", "body": "x"})
    verify = await client.get(
        f"/api/v1/organizations/{user.org_id}/audit/verify", headers=user.auth)
    assert verify.json()["intact"] is True

    # Tamper with a row, then verification must fail.
    async with container.database.session_factory() as session:
        row = (await session.execute(select(AuditLog).limit(1))).scalar_one()
        row.action = "tampered.action"
        await session.commit()
    verify2 = await client.get(
        f"/api/v1/organizations/{user.org_id}/audit/verify", headers=user.auth)
    assert verify2.json()["intact"] is False


async def test_consent_management(client, register_user):
    user = await register_user("consent@example.com")
    put = await client.put("/api/v1/me/consents", headers=user.auth,
                           json={"consent_type": "analytics", "granted": True})
    assert put.status_code == 200
    assert put.json()["granted"] is True

    got = await client.get("/api/v1/me/consents", headers=user.auth)
    analytics = [c for c in got.json() if c["consent_type"] == "analytics"][0]
    assert analytics["granted"] is True


async def test_retention_purge_removes_expired_soft_deleted(container, client,
                                                            register_user):
    user = await register_user("ret@example.com")
    note = await client.post(f"/api/v1/organizations/{user.org_id}/notes",
                             headers=user.auth, json={"title": "old", "body": "b"})
    note_id = note.json()["id"]
    await client.delete(
        f"/api/v1/organizations/{user.org_id}/notes/{note_id}", headers=user.auth)

    # Force the deletion timestamp far into the past, past the retention window.
    from datetime import datetime, timedelta, timezone
    async with container.database.session_factory() as session:
        row = await session.get(Note, note_id)
        row.deleted_at = datetime.now(timezone.utc) - timedelta(days=400)
        await session.commit()

    purge = await client.post(
        f"/api/v1/organizations/{user.org_id}/retention/purge", headers=user.auth)
    assert purge.status_code == 200
    assert purge.json()["notes"] >= 1
    async with container.database.session_factory() as session:
        assert (await session.get(Note, note_id)) is None
