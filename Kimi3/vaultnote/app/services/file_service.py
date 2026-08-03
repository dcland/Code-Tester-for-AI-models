"""
File service - secure upload, magic-byte validation, encrypted storage,
short-lived download tokens, path-traversal protection.
"""
from __future__ import annotations

import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.encryption import WrappedKey, encryption_service
from app.core.security import generate_secure_token, hash_token
from app.models.entities import DownloadToken, FileAsset
from app.repositories.repositories import DownloadTokenRepository, FileRepository, OrganizationRepository
from app.utils.exceptions import NotFoundError, ValidationError

# Magic bytes for allowed file types
_MAGIC = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"%PDF": "application/pdf",
    b"PK\x03\x04": "application/zip",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
}

_SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9._-]")


def _sanitize_filename(name: str) -> str:
    """Path-traversal protection: strip directories and unsafe chars."""
    name = os.path.basename(name)  # remove any path components
    name = _SAFE_FILENAME_RE.sub("_", name)
    return name[:255] or "file"


def _sniff_mime(data: bytes) -> str | None:
    for magic, mime in _MAGIC.items():
        if data.startswith(magic):
            return mime
    return None


async def _stub_virus_scan(data: bytes) -> bool:
    """Virus scan stub - returns True if clean. Pluggable interface."""
    return True


class FileService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.files = FileRepository(session)
        self.orgs = OrganizationRepository(session)
        self.tokens = DownloadTokenRepository(session)

    async def _tenant_kek(self, org_id: str) -> bytes:
        org = await self.orgs.get_by_id(org_id)
        if org is None:
            raise NotFoundError("Organization not found")
        return encryption_service.decrypt_kek(WrappedKey(org.kek_ciphertext, org.kek_nonce))

    async def upload_file(
        self, org_id: str, workspace_id: str, user_id: str,
        filename: str, data: bytes,
    ) -> FileAsset:
        if len(data) > settings.MAX_FILE_SIZE_BYTES:
            raise ValidationError("File too large")
        if len(data) == 0:
            raise ValidationError("Empty file")

        mime = _sniff_mime(data)
        if mime is None:
            raise ValidationError("Unsupported file type")
        if not await _stub_virus_scan(data):
            raise ValidationError("File failed virus scan")

        safe_name = _sanitize_filename(filename)
        kek = await self._tenant_kek(org_id)
        dek = encryption_service.generate_dek()

        # Encrypt filename and content
        fname_ct, fname_nonce = encryption_service.encrypt(safe_name.encode(), dek)
        content_ct, content_nonce = encryption_service.encrypt(data, dek)
        wrapped = encryption_service.wrap_dek(dek, kek)

        # Random storage path prevents traversal and enumeration
        storage_name = f"{secrets.token_hex(16)}.enc"
        storage_dir = Path(settings.FILE_STORAGE_PATH)
        storage_dir.mkdir(parents=True, exist_ok=True)
        storage_path = storage_dir / storage_name

        # Persist encrypted content + nonce as header
        with open(storage_path, "wb") as f:
            f.write(content_nonce.encode() + b"\n" + content_ct.encode())

        asset = FileAsset(
            organization_id=org_id, workspace_id=workspace_id,
            filename_encrypted=fname_ct, filename_nonce=fname_nonce,
            dek_ciphertext=wrapped.ciphertext, dek_nonce=wrapped.nonce,
            storage_path=str(storage_path), size_bytes=len(data),
            mime_type=mime, uploaded_by=user_id,
        )
        await self.files.create(asset)
        return asset

    async def get_file_meta(self, org_id: str, file_id: str) -> dict:
        asset = await self.files.get_by_id_and_org(file_id, org_id)
        if asset is None or asset.deleted_at is not None:
            raise NotFoundError("File not found")
        kek = await self._tenant_kek(org_id)
        dek = encryption_service.unwrap_dek(WrappedKey(asset.dek_ciphertext, asset.dek_nonce), kek)
        filename = encryption_service.decrypt(asset.filename_encrypted, asset.filename_nonce, dek).decode()
        return {"id": asset.id, "filename": filename, "size_bytes": asset.size_bytes, "mime_type": asset.mime_type}

    async def create_download_token(self, org_id: str, file_id: str) -> str:
        asset = await self.files.get_by_id_and_org(file_id, org_id)
        if asset is None:
            raise NotFoundError("File not found")
        token = generate_secure_token(32)
        dt = DownloadToken(
            file_id=asset.id, token_hash=hash_token(token),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=settings.DOWNLOAD_TOKEN_EXPIRE_SECONDS),
        )
        await self.tokens.create(dt)
        return token

    async def download_file(self, org_id: str, token: str) -> tuple[str, bytes, str]:
        token_hash = hash_token(token)
        dt = await self.tokens.get_by_hash(token_hash)
        if dt is None or dt.used:
            raise ValidationError("Invalid or expired download token")
        # SQLite returns naive datetimes - normalize for comparison
        expires = dt.expires_at.replace(tzinfo=timezone.utc) if dt.expires_at.tzinfo is None else dt.expires_at
        if expires < datetime.now(timezone.utc):
            raise ValidationError("Invalid or expired download token")
        asset = await self.files.get_by_id_and_org(dt.file_id, org_id)
        if asset is None:
            raise NotFoundError("File not found")

        # Path-traversal defense: resolve and confine to storage dir
        storage_dir = Path(settings.FILE_STORAGE_PATH).resolve()
        file_path = Path(asset.storage_path).resolve()
        if not str(file_path).startswith(str(storage_dir)):
            raise ValidationError("Invalid storage path")
        raw = file_path.read_bytes()
        nonce_b64, ct_b64 = raw.split(b"\n", 1)

        kek = await self._tenant_kek(org_id)
        dek = encryption_service.unwrap_dek(WrappedKey(asset.dek_ciphertext, asset.dek_nonce), kek)
        plaintext = encryption_service.decrypt(ct_b64.decode(), nonce_b64.decode(), dek)
        filename = encryption_service.decrypt(asset.filename_encrypted, asset.filename_nonce, dek).decode()

        dt.used = True
        await self.session.flush()
        return filename, plaintext, asset.mime_type
