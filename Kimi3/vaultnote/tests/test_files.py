"""Tests: secure file upload (raw body), magic-byte + declared-MIME validation,
virus scanning, download tokens, path traversal, deletion."""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.conftest import headers

_PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x00IEND\xaeB`\x82")

_EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


async def _make_workspace(client: AsyncClient, auth: dict) -> str:
    r = await client.post("/api/v1/workspaces", json={"name": "WS"}, headers=headers(auth))
    return r.json()["id"]


async def _upload(client: AsyncClient, auth: dict, ws: str, data: bytes = _PNG,
                  filename: str = "logo.png", mime: str = "image/png") -> dict:
    r = await client.post(f"/api/v1/workspaces/{ws}/files", content=data,
                          headers={**headers(auth), "Content-Type": mime,
                                   "X-File-Name": filename})
    return r


@pytest.mark.asyncio
async def test_upload_valid_png(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await _upload(client, auth_a, ws)
    assert r.status_code == 201
    assert r.json()["mime_type"] == "image/png"


@pytest.mark.asyncio
async def test_upload_disallowed_type_rejected(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    exe = b"MZ\x90\x00" + b"\x00" * 100  # PE executable magic
    r = await _upload(client, auth_a, ws, exe, "evil.exe", "application/octet-stream")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_upload_fake_extension_rejected(client: AsyncClient, auth_a):
    """A .png file with non-PNG magic bytes is rejected (magic-byte validation)."""
    ws = await _make_workspace(client, auth_a)
    fake = b"NOT A REAL PNG CONTENT"
    r = await _upload(client, auth_a, ws, fake, "fake.png", "image/png")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_declared_mime_must_match_magic(client: AsyncClient, auth_a):
    """The declared Content-Type must agree with the detected magic bytes."""
    ws = await _make_workspace(client, auth_a)
    # PNG bytes but declared as JPEG -> mismatch -> reject
    r = await _upload(client, auth_a, ws, _PNG, "photo.jpg", "image/jpeg")
    assert r.status_code == 422
    # Generic octet-stream declaration is accepted and sniffed instead
    r2 = await _upload(client, auth_a, ws, _PNG, "blob.bin", "application/octet-stream")
    assert r2.status_code == 201
    assert r2.json()["mime_type"] == "image/png"


@pytest.mark.asyncio
async def test_virus_signature_rejected(client: AsyncClient, auth_a):
    """The virus scanner has a real reject path (EICAR test signature)."""
    ws = await _make_workspace(client, auth_a)
    payload = _PNG + _EICAR  # valid type, malicious content
    r = await _upload(client, auth_a, ws, payload, "evil.png", "image/png")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_path_traversal_filename_sanitized(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await _upload(client, auth_a, ws, _PNG, "../../../etc/passwd.png")
    assert r.status_code == 201
    file_id = r.json()["id"]
    meta = await client.get(f"/api/v1/workspaces/{ws}/files/{file_id}", headers=headers(auth_a))
    assert ".." not in meta.json()["filename"]


@pytest.mark.asyncio
async def test_file_encrypted_at_rest(client: AsyncClient, auth_a, db_session):
    """File bytes on disk must be ciphertext."""
    from sqlalchemy import select

    from app.models.entities import FileAsset
    ws = await _make_workspace(client, auth_a)
    r = await _upload(client, auth_a, ws, _PNG, "doc.png")
    assert r.status_code == 201
    result = await db_session.execute(select(FileAsset))
    asset = result.scalar_one()
    from pathlib import Path
    raw = Path(asset.storage_path).read_bytes()
    assert _PNG not in raw  # plaintext not present on disk


@pytest.mark.asyncio
async def test_download_token_flow(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await _upload(client, auth_a, ws)
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
    r = await _upload(client, auth_a, ws, _PNG, "a.png")
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
    r = await _upload(client, auth_a, ws, _PNG, "a.png")
    file_id = r.json()["id"]
    r2 = await client.get(f"/api/v1/workspaces/{ws}/files/{file_id}/download?token=bogus",
                          headers=headers(auth_a))
    assert r2.status_code == 422


@pytest.mark.asyncio
async def test_empty_file_rejected(client: AsyncClient, auth_a):
    ws = await _make_workspace(client, auth_a)
    r = await _upload(client, auth_a, ws, b"", "empty.png")
    assert r.status_code == 422


# ---- File deletion (previously missing entirely) ----------------------------

@pytest.mark.asyncio
async def test_delete_file_removes_blob_and_row(client: AsyncClient, auth_a, db_session):
    """DELETE removes the metadata AND the encrypted blob from disk."""
    from pathlib import Path

    from sqlalchemy import select

    from app.models.entities import FileAsset
    ws = await _make_workspace(client, auth_a)
    r = await _upload(client, auth_a, ws, _PNG, "todelete.png")
    file_id = r.json()["id"]
    asset = (await db_session.execute(select(FileAsset))).scalar_one()
    blob = Path(asset.storage_path)
    assert blob.exists()

    r2 = await client.delete(f"/api/v1/workspaces/{ws}/files/{file_id}", headers=headers(auth_a))
    assert r2.status_code == 204
    assert not blob.exists()  # physical blob is gone
    r3 = await client.get(f"/api/v1/workspaces/{ws}/files/{file_id}", headers=headers(auth_a))
    assert r3.status_code == 404


@pytest.mark.asyncio
async def test_delete_file_permission(client: AsyncClient, auth_a, member_a):
    """Only the uploader or an org owner/admin may delete a file."""
    ws = await _make_workspace(client, auth_a)
    r = await _upload(client, auth_a, ws, _PNG, "guard.png")
    file_id = r.json()["id"]
    # A different member (not uploader, not admin) is forbidden
    r2 = await client.delete(f"/api/v1/workspaces/{ws}/files/{file_id}", headers=headers(member_a))
    assert r2.status_code == 403
    # The uploader (owner here) can delete
    r3 = await client.delete(f"/api/v1/workspaces/{ws}/files/{file_id}", headers=headers(auth_a))
    assert r3.status_code == 204


@pytest.mark.asyncio
async def test_cross_tenant_file_access_denied(client: AsyncClient, auth_a, auth_b):
    ws = await _make_workspace(client, auth_a)
    r = await _upload(client, auth_a, ws, _PNG, "a.png")
    file_id = r.json()["id"]
    r2 = await client.get(f"/api/v1/workspaces/{ws}/files/{file_id}", headers=headers(auth_b))
    assert r2.status_code in (403, 404)
