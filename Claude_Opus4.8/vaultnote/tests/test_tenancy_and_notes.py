"""Multi-tenant isolation, notes CRUD, access control, and collaboration."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def _make_note(client, user, title="Secret", body="hello"):
    resp = await client.post(f"/api/v1/organizations/{user.org_id}/notes",
                             headers=user.auth,
                             json={"title": title, "body": body})
    assert resp.status_code == 201, resp.text
    return resp.json()


async def test_note_crud_roundtrip(client, register_user):
    user = await register_user("owner@example.com")
    note = await _make_note(client, user, "My Title", "My Body")
    assert note["title"] == "My Title"

    got = await client.get(
        f"/api/v1/organizations/{user.org_id}/notes/{note['id']}", headers=user.auth)
    assert got.status_code == 200
    assert got.json()["body"] == "My Body"

    upd = await client.patch(
        f"/api/v1/organizations/{user.org_id}/notes/{note['id']}",
        headers=user.auth, json={"body": "Edited"})
    assert upd.status_code == 200
    assert upd.json()["body"] == "Edited"
    assert upd.json()["version"] == 2

    listing = await client.get(
        f"/api/v1/organizations/{user.org_id}/notes", headers=user.auth)
    assert any(n["id"] == note["id"] for n in listing.json())

    delete = await client.delete(
        f"/api/v1/organizations/{user.org_id}/notes/{note['id']}", headers=user.auth)
    assert delete.status_code == 204
    gone = await client.get(
        f"/api/v1/organizations/{user.org_id}/notes/{note['id']}", headers=user.auth)
    assert gone.status_code == 404


async def test_optimistic_concurrency_conflict(client, register_user):
    user = await register_user("occ@example.com")
    note = await _make_note(client, user)
    # Stale expected_version triggers a conflict.
    resp = await client.patch(
        f"/api/v1/organizations/{user.org_id}/notes/{note['id']}",
        headers=user.auth, json={"body": "x", "expected_version": 99})
    assert resp.status_code == 409


async def test_tenant_isolation_cross_org_denied(client, register_user):
    alice = await register_user("t-alice@example.com", org="Alice Org")
    bob = await register_user("t-bob@example.com", org="Bob Org")
    note = await _make_note(client, alice, "Alice secret", "confidential")

    # Bob cannot list or read Alice's org (not a member) -> 403.
    listing = await client.get(
        f"/api/v1/organizations/{alice.org_id}/notes", headers=bob.auth)
    assert listing.status_code == 403

    # Even naming Alice's note id under Bob's own org yields 404 (isolation).
    cross = await client.get(
        f"/api/v1/organizations/{bob.org_id}/notes/{note['id']}", headers=bob.auth)
    assert cross.status_code == 404


async def test_viewer_cannot_create_note(client, register_user):
    owner = await register_user("v-owner@example.com", org="Shared")
    viewer = await register_user("v-viewer@example.com", org="ViewerOwn")
    # Invite viewer into owner's org as viewer.
    inv = await client.post(
        f"/api/v1/organizations/{owner.org_id}/members", headers=owner.auth,
        json={"email": "v-viewer@example.com", "role": "viewer"})
    assert inv.status_code == 201
    resp = await client.post(
        f"/api/v1/organizations/{owner.org_id}/notes", headers=viewer.auth,
        json={"title": "nope", "body": ""})
    assert resp.status_code == 422


async def test_member_cannot_delete_others_note(client, register_user):
    owner = await register_user("m-owner@example.com", org="Team")
    member = await register_user("m-member@example.com", org="MemberOwn")
    await client.post(
        f"/api/v1/organizations/{owner.org_id}/members", headers=owner.auth,
        json={"email": "m-member@example.com", "role": "member"})
    note = await _make_note(client, owner, "owner note")
    # Member has no share; cannot even read (broken-access-control check).
    read = await client.get(
        f"/api/v1/organizations/{owner.org_id}/notes/{note['id']}", headers=member.auth)
    assert read.status_code == 403
    delete = await client.delete(
        f"/api/v1/organizations/{owner.org_id}/notes/{note['id']}", headers=member.auth)
    assert delete.status_code == 403


async def test_admin_role_change_and_removal(client, register_user):
    owner = await register_user("r-owner@example.com", org="RoleOrg")
    other = await register_user("r-other@example.com", org="OtherOwn")
    await client.post(
        f"/api/v1/organizations/{owner.org_id}/members", headers=owner.auth,
        json={"email": "r-other@example.com", "role": "member"})
    promote = await client.patch(
        f"/api/v1/organizations/{owner.org_id}/members/{other.user_id}",
        headers=owner.auth, json={"role": "admin"})
    assert promote.status_code == 204
    remove = await client.delete(
        f"/api/v1/organizations/{owner.org_id}/members/{other.user_id}",
        headers=owner.auth)
    assert remove.status_code == 204


async def test_collaboration_presence_and_ops(client, register_user):
    user = await register_user("collab@example.com")
    note = await _make_note(client, user, "Doc", "abcdef")
    pres = await client.post(
        f"/api/v1/organizations/{user.org_id}/notes/{note['id']}/presence",
        headers=user.auth)
    assert pres.status_code == 200
    assert user.user_id in pres.json()["active_user_ids"]

    op = await client.post(
        f"/api/v1/organizations/{user.org_id}/notes/{note['id']}/operations",
        headers=user.auth,
        json={"base_version": note["version"], "op": "insert",
              "position": 0, "text": "X"})
    assert op.status_code == 200
    assert op.json()["body"].startswith("X")


async def test_note_content_encrypted_at_rest(container, register_user, client):
    user = await register_user("enc@example.com")
    note = await _make_note(client, user, "PLAINTITLE", "PLAINBODY")
    # Inspect the raw DB row: ciphertext must not contain the plaintext.
    from sqlalchemy import select

    from app.models.content import Note
    async with container.database.session_factory() as session:
        row = (await session.execute(
            select(Note).where(Note.id == note["id"]))).scalar_one()
        assert b"PLAINTITLE" not in row.title_ciphertext
        assert b"PLAINBODY" not in row.body_ciphertext
