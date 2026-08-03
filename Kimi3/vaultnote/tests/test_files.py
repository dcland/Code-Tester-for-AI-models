"""Tests: secure file upload, magic-byte validation, download tokens, path traversal."""
from __future__ import annotations

import io

import pytest
from httpx import AsyncClient

from tests.conftest import headers

_PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x00IEND\xaeB`\x82")


async def _make_workspace(client: AsyncClient, auth: dict) -> str:
    r = await client.post("/api/v1/workspaces", json={"name": "WS"}, headers=headers(auth))
    return r.json()["id"]


@pytest.mark.asyncio
async def test_upload_valid_png(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/files",
                          files={"file": ("logo.png", io.BytesIO(_PNG), "image/png")},
                          headers=headers(auth_a))
    assert r.status_code == 201
    assert r.json()["mime_type"] == "image/png"


@pytest.mark.asyncio
async def test_upload_disallowed_type_rejected(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    exe = b"MZ\x90\x00" + b"\x00" * 100  # PE executable magic
    r = await client.post(f"/api/v1/workspaces/{ws}/files",
                          files={"file": ("evil.exe", io.BytesIO(exe), "application/octet-stream")},
                          headers=headers(auth_a))
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_upload_fake_extension_rejected(client: AsyncClient, auth_a):
    """A .png file with non-PNG magic bytes is rejected (magic-byte validation)."""
    ws = await _make_workspace(client, auth_a)
    fake = b"NOT A REAL PNG CONTENT"
    r = await client.post(f"/api/v1/workspaces/{ws}/files",
                          files={"file": ("fake.png", io.BytesIO(fake), "image/png")},
                          headers=headers(auth_a))
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_path_traversal_filename_sanitized(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/files",
                          files={"file": ("../../../etc/passwd.png", io.BytesIO(_PNG), "image/png")},
                          headers=headers(auth_a))
    assert r.status_code == 201
    # Stored path must not contain traversal
    file_id = r.json()["id"]
    meta = await client.get(f"/api/v1/workspaces/{ws}/files/{file_id}", headers=headers(auth_a))
    assert ".." not in meta.json()["filename"]


@pytest.mark.asyncio
async def test_file_encrypted_at_rest(client: AsyncClient, auth_a, db_session):
    """File bytes on disk must be ciphertext."""
    from sqlalchemy import select
    from app.models.entities import FileAsset
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/files",
                          files={"file": ("doc.png", io.BytesIO(_PNG), "image/png")},
                          headers=headers(auth_a))
    assert r.status_code == 201
    result = await db_session.execute(select(FileAsset))
    asset = result.scalar_one()
    from pathlib import Path
    raw = Path(asset.storage_path).read_bytes()
    assert _PNG not in raw  # plaintext not present on disk


@pytest.mark.asyncio
async def test_download_token_flow(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/files",
                          files={"file": ("logo.png", io.BytesIO(_PNG), "image/png")},
                          headers=headers(auth_a))
    file_id = r.json()["id"]
    r2 = await client.post(f"/api/v1/workspaces/{ws}/files/{file_id}/download-token",
                           headers=headers(auth_a))
    assert r2.status_code == 201
    token = r2.json()["download_token"]
    r3 = await client.get(f"/api/v1/workspaces/{ws}/files/{file_id}/download?token={token}",
                          headers=headers(auth_a))
    assert r3.status_code == 200
    assert r3.content == _PNG


@pytest.mark.asyncio
async def test_download_token_single_use(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/files",
                          files={"file": ("a.png", io.BytesIO(_PNG), "image/png")},
                          headers=headers(auth_a))
    file_id = r.json()["id"]
    token = (await client.post(f"/api/v1/workspaces/{ws}/files/{file_id}/download-token",
                               headers=headers(auth_a))).json()["download_token"]
    r1 = await client.get(f"/api/v1/workspaces/{ws}/files/{file_id}/download?token={token}",
                          headers=headers(auth_a))
    assert r1.status_code == 200
    r2 = await client.get(f"/api/v1/workspaces/{ws}/files/{file_id}/download?token={token}",
                          headers=headers(auth_a))
    assert r2.status_code == 422  # already used


@pytest.mark.asyncio
async def test_download_invalid_token(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/files",
                          files={"file": ("a.png", io.BytesIO(_PNG), "image/png")},
                          headers=headers(auth_a))
    file_id = r.json()["id"]
    r2 = await client.get(f"/api/v1/workspaces/{ws}/files/{file_id}/download?token=bogus",
                          headers=headers(auth_a))
    assert r2.status_code == 422


@pytest.mark.asyncio
async def test_empty_file_rejected(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await client.post(f"/api/v1/workspaces/{ws}/files",
                          files={"file": ("empty.png", io.BytesIO(b""), "image/png")},
                          headers=headers(auth_a))
    assert r.status_code == 422
