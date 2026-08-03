"""Tests: notes CRUD, multi-tenant isolation, access control, collaboration."""
from __future__ import annotations

import time

import pytest
from httpx import AsyncClient

from tests.conftest import headers


async def _make_workspace(client: AsyncClient, auth: dict) -> str:
    r = await client.post("/api/v1/workspaces", json={"name": "WS"}, headers=headers(auth))
    assert r.status_code == 201
    return r.json()["id"]


@pytest.mark.asyncio
async def test_create_and_get_note(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/notes",
                          json={"title": "Secret Plan", "content": "Top secret"},
                          headers=headers(auth_a))
    assert r.status_code == 201
    note_id = r.json()["id"]
    r2 = await client.get(f"/api/v1/workspaces/{ws}/notes/{note_id}", headers=headers(auth_a))
    assert r2.status_code == 200
    assert r2.json()["title"] == "Secret Plan"
    assert r2.json()["content"] == "Top secret"


@pytest.mark.asyncio
async def test_note_content_encrypted_at_rest(client: AsyncClient, auth_a, db_session):
    """Verify note content in DB is ciphertext, not plaintext."""
    from sqlalchemy import select
    from app.models.entities import Note
    ws = await _make_workspace(client, auth_a)
    await client.post(f"/api/v1/workspaces/{ws}/notes",
                      json={"title": "PlainTitle", "content": "PlainContent123"},
                      headers=headers(auth_a))
    result = await db_session.execute(select(Note))
    note = result.scalar_one()
    assert "PlainTitle" not in note.title_encrypted
    assert "PlainContent123" not in note.content_encrypted


@pytest.mark.asyncio
async def test_cross_tenant_note_access_denied(client: AsyncClient, auth_a, auth_b):
    """Multi-tenancy isolation: Org B cannot read Org A's note."""
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/notes",
                          json={"title": "A Only", "content": "private"},
                          headers=headers(auth_a))
    note_id = r.json()["id"]
    # Org B tries to access Org A's note with Org B's org id
    r2 = await client.get(f"/api/v1/workspaces/{ws}/notes/{note_id}", headers=headers(auth_b))
    assert r2.status_code == 404  # not found (no existence leak)


@pytest.mark.asyncio
async def test_cross_tenant_org_header_rejected(client: AsyncClient, auth_a, auth_b):
    """User from Org A cannot use Org B's organization ID."""
    r = await client.get("/api/v1/workspaces", headers={
        "Authorization": f"Bearer {auth_a['token']}",
        "X-Organization-ID": auth_b["org_id"],
    })
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_sql_injection_in_note_title(client: AsyncClient, auth_a):
    """SQL injection attempt is safely treated as data (parameterized queries)."""
    ws = await _make_workspace(client, auth_a)
    payload = "'; DROP TABLE notes; --"
    r = await client.post(f"/api/v1/workspaces/{ws}/notes",
                          json={"title": payload, "content": "x"},
                          headers=headers(auth_a))
    assert r.status_code == 201
    # Table still exists - we can list notes
    r2 = await client.get(f"/api/v1/workspaces/{ws}/notes", headers=headers(auth_a))
    assert r2.status_code == 200
    assert r2.json()[0]["title"] == payload


@pytest.mark.asyncio
async def test_update_note(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/notes",
                          json={"title": "v1", "content": "c1"}, headers=headers(auth_a))
    note_id = r.json()["id"]
    r2 = await client.patch(f"/api/v1/workspaces/{ws}/notes/{note_id}",
                            json={"content": "c2"}, headers=headers(auth_a))
    assert r2.status_code == 200
    assert r2.json()["version"] == 2


@pytest.mark.asyncio
async def test_delete_note(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/notes",
                          json={"title": "t", "content": "c"}, headers=headers(auth_a))
    note_id = r.json()["id"]
    r2 = await client.delete(f"/api/v1/workspaces/{ws}/notes/{note_id}", headers=headers(auth_a))
    assert r2.status_code == 204
    r3 = await client.get(f"/api/v1/workspaces/{ws}/notes/{note_id}", headers=headers(auth_a))
    assert r3.status_code == 404


@pytest.mark.asyncio
async def test_nested_folders(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r1 = await client.post(f"/api/v1/workspaces/{ws}/folders",
                           json={"name": "Parent"}, headers=headers(auth_a))
    parent_id = r1.json()["id"]
    r2 = await client.post(f"/api/v1/workspaces/{ws}/folders",
                           json={"name": "Child", "parent_id": parent_id},
                           headers=headers(auth_a))
    assert r2.status_code == 201
    r3 = await client.get(f"/api/v1/workspaces/{ws}/folders?parent_id={parent_id}",
                          headers=headers(auth_a))
    assert any(f["name"] == "Child" for f in r3.json())


@pytest.mark.asyncio
async def test_share_note_with_user(client: AsyncClient, auth_a, auth_b):
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/notes",
                          json={"title": "Shared", "content": "c"}, headers=headers(auth_a))
    note_id = r.json()["id"]
    r2 = await client.post(f"/api/v1/workspaces/{ws}/notes/{note_id}/share",
                           json={"grantee_user_id": auth_b["user_id"], "permission": "read"},
                           headers=headers(auth_a))
    assert r2.status_code == 201


@pytest.mark.asyncio
async def test_share_link_creation(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/notes",
                          json={"title": "Link", "content": "c"}, headers=headers(auth_a))
    note_id = r.json()["id"]
    r2 = await client.post(f"/api/v1/workspaces/{ws}/notes/{note_id}/share-link",
                           json={"permission": "read", "expires_in_hours": 24},
                           headers=headers(auth_a))
    assert r2.status_code == 201
    assert "token" in r2.json()


@pytest.mark.asyncio
async def test_collaboration_operations(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/notes",
                          json={"title": "Collab", "content": "abc"}, headers=headers(auth_a))
    note_id = r.json()["id"]
    r2 = await client.post(f"/api/v1/workspaces/{ws}/notes/{note_id}/operations",
                           json={"op_type": "insert", "position": 3, "content": "d"},
                           headers=headers(auth_a))
    assert r2.status_code == 201
    assert r2.json()["lamport"] == 1
    r3 = await client.get(f"/api/v1/workspaces/{ws}/notes/{note_id}/operations",
                          headers=headers(auth_a))
    assert len(r3.json()) == 1
    assert r3.json()[0]["content"] == "d"


@pytest.mark.asyncio
async def test_presence_update_and_get(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/notes",
                          json={"title": "P", "content": "c"}, headers=headers(auth_a))
    note_id = r.json()["id"]
    await client.post(f"/api/v1/workspaces/{ws}/notes/{note_id}/presence",
                      json={"cursor_position": 5}, headers=headers(auth_a))
    r2 = await client.get(f"/api/v1/workspaces/{ws}/notes/{note_id}/presence",
                          headers=headers(auth_a))
    assert len(r2.json()) == 1
    assert r2.json()[0]["cursor_position"] == 5


@pytest.mark.asyncio
async def test_key_rotation_preserves_decryption(client: AsyncClient, auth_a):
    """After rotating tenant KEK, existing notes must still decrypt."""
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/notes",
                          json={"title": "RotTest", "content": "secret123"},
                          headers=headers(auth_a))
    note_id = r.json()["id"]
    r2 = await client.post("/api/v1/admin/keys/rotate", headers=headers(auth_a))
    assert r2.status_code == 200
    assert r2.json()["rewrapped_items"] >= 1
    r3 = await client.get(f"/api/v1/workspaces/{ws}/notes/{note_id}", headers=headers(auth_a))
    assert r3.json()["content"] == "secret123"


@pytest.mark.asyncio
async def test_get_note_performance(client: AsyncClient, auth_a):
    """Performance smoke: cached note reads must be fast."""
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/notes",
                          json={"title": "Perf", "content": "c"}, headers=headers(auth_a))
    note_id = r.json()["id"]
    # Warm the cache
    await client.get(f"/api/v1/workspaces/{ws}/notes/{note_id}", headers=headers(auth_a))
    start = time.perf_counter()
    for _ in range(20):
        await client.get(f"/api/v1/workspaces/{ws}/notes/{note_id}", headers=headers(auth_a))
    avg_ms = (time.perf_counter() - start) / 20 * 1000
    assert avg_ms < 200  # generous bound for in-process test client
