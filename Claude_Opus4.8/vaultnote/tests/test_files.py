"""File upload/download security tests."""

from __future__ import annotations

import pytest

from app.core.exceptions import FileValidationError
from app.utils.files import BlobStore, sniff_content_type, validate_upload

# asyncio_mode=auto auto-detects coroutine tests; sync helpers run as-is.

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


async def _upload(client, user, data: bytes, filename: str, content_type: str):
    return await client.post(
        f"/api/v1/organizations/{user.org_id}/files",
        headers={**user.auth, "X-Filename": filename, "Content-Type": content_type},
        content=data,
    )


async def test_upload_and_download_roundtrip(client, register_user):
    user = await register_user("f-user@example.com")
    up = await _upload(client, user, PNG, "pic.png", "image/png")
    assert up.status_code == 201, up.text
    file_id = up.json()["id"]

    tok = await client.post(
        f"/api/v1/organizations/{user.org_id}/files/{file_id}/download-token",
        headers=user.auth)
    assert tok.status_code == 200
    token = tok.json()["token"]

    dl = await client.get(
        f"/api/v1/organizations/{user.org_id}/files/download",
        headers=user.auth, params={"token": token})
    assert dl.status_code == 200
    assert dl.content == PNG


async def test_upload_rejects_disallowed_type(client, register_user):
    user = await register_user("f-bad@example.com")
    # Windows PE executable magic bytes "MZ" -> not in allow-list.
    resp = await _upload(client, user, b"MZ\x90\x00" + b"\x00" * 32,
                         "evil.exe", "application/octet-stream")
    assert resp.status_code == 422


async def test_upload_rejects_eicar(client, register_user):
    user = await register_user("f-virus@example.com")
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    resp = await _upload(client, user, eicar, "test.txt", "text/plain")
    assert resp.status_code == 422


async def test_magic_byte_sniffing_overrides_client_claim():
    # Client claims PNG but bytes are plain text -> classified as text.
    result = sniff_content_type(b"just some text, not a png")
    assert result.content_type == "text/plain"


def test_validate_upload_enforces_size():
    with pytest.raises(FileValidationError):
        validate_upload(b"%PDF-" + b"0" * 100, max_bytes=10,
                        declared_content_type="application/pdf")


def test_blob_store_blocks_path_traversal(tmp_path):
    store = BlobStore(str(tmp_path))
    with pytest.raises(FileValidationError):
        store.write("../../etc/passwd", b"x")
    with pytest.raises(FileValidationError):
        store.read("..%2f..%2fetc")


async def test_download_token_required(client, register_user):
    user = await register_user("f-tok@example.com")
    up = await _upload(client, user, PNG, "pic.png", "image/png")
    file_id = up.json()["id"]
    # Forged/garbage token is rejected.
    dl = await client.get(
        f"/api/v1/organizations/{user.org_id}/files/download",
        headers=user.auth, params={"token": "not-a-real-token"})
    assert dl.status_code == 401


async def test_file_encrypted_at_rest(container, client, register_user):
    user = await register_user("f-enc@example.com")
    secret = b"\x89PNG\r\n\x1a\n" + b"SUPERSECRETMARKER" + b"\x00" * 16
    up = await _upload(client, user, secret, "s.png", "image/png")
    file_id = up.json()["id"]
    from sqlalchemy import select

    from app.models.content import File
    async with container.database.session_factory() as session:
        row = (await session.execute(
            select(File).where(File.id == file_id))).scalar_one()
        blob = container.blob_store.read(row.storage_key)
        assert b"SUPERSECRETMARKER" not in blob        # encrypted on disk
        assert b"s.png" not in row.filename_ciphertext  # filename encrypted too
