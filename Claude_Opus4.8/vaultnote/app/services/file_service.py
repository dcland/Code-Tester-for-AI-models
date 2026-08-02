"""Secure file upload/download service (encrypted at rest)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance import AuditAction
from app.core.config import Settings
from app.core.encryption import EnvelopeEncryptor
from app.core.exceptions import (
    InvalidTokenError,
    NotFoundError,
    QuotaExceededError,
    ValidationError,
)
from app.core.security import SecurityService
from app.db.base import new_id
from app.models.content import File
from app.models.organization import Role
from app.repositories import FileRepository, FolderRepository, OrganizationRepository
from app.services.access_service import AccessService
from app.services.audit_service import AuditService
from app.services.billing_service import PLAN_LIMITS
from app.utils.files import BlobStore, scan_for_malware, validate_upload


def _file_aad(org_id: str, file_id: str) -> bytes:
    return f"file:{org_id}:{file_id}".encode()


@dataclass
class DecryptedFile:
    id: str
    filename: str
    content_type: str
    size_bytes: int
    data: bytes


class FileService:
    def __init__(self, session: AsyncSession, settings: Settings,
                 encryptor: EnvelopeEncryptor, security: SecurityService,
                 blob_store: BlobStore) -> None:
        self._s = session
        self._settings = settings
        self._enc = encryptor
        self._sec = security
        self._blobs = blob_store
        self._files = FileRepository(session)
        self._folders = FolderRepository(session)
        self._orgs = OrganizationRepository(session)
        self._access = AccessService(session)
        self._audit = AuditService(session, settings)

    async def _tenant_key(self, org_id: str) -> bytes:
        org = await self._orgs.get(org_id)
        if org is None:
            raise NotFoundError("organization not found")
        return org.wrapped_master_key

    async def upload(self, org_id: str, user_id: str, *, filename: str,
                     data: bytes, declared_content_type: str | None,
                     folder_id: str | None) -> File:
        role = await self._access.require_membership(org_id, user_id)
        if role is Role.VIEWER:
            raise ValidationError("viewers cannot upload files")

        # 1) Validate BEFORE doing any expensive work (size, magic bytes).
        sniff = validate_upload(
            data, max_bytes=self._settings.max_upload_bytes,
            declared_content_type=declared_content_type,
        )
        # 2) Malware scan (stub interface).
        scan_for_malware(data)

        # 3) Quota / storage metering enforcement.
        org = await self._orgs.get(org_id)
        limit = PLAN_LIMITS[org.plan].storage_bytes
        used = await self._files.total_storage(org_id)
        if used + len(data) > limit:
            raise QuotaExceededError("storage quota exceeded for current plan")

        if folder_id is not None and await self._folders.get(org_id, folder_id) is None:
            raise NotFoundError("folder not found")

        file_id = new_id()
        storage_key = new_id() + new_id()  # 64-char opaque, not derived from name
        tmk = await self._tenant_key(org_id)
        # Encrypt file bytes and the (potentially sensitive) filename together.
        (blob_ct, name_ct), wrapped = self._enc.encrypt_many(
            tmk, [data, filename.encode()], _file_aad(org_id, file_id)
        )
        self._blobs.write(storage_key, blob_ct)

        record = File(
            id=file_id, org_id=org_id, folder_id=folder_id, owner_id=user_id,
            filename_ciphertext=name_ct, content_type=sniff.content_type,
            size_bytes=len(data), storage_key=storage_key, wrapped_dek=wrapped,
            content_sha256=hashlib.sha256(data).hexdigest(),
        )
        await self._files.add(record)
        await self._audit.record(
            action=AuditAction.FILE_UPLOADED, org_id=org_id, actor_user_id=user_id,
            resource_type="file", resource_id=file_id,
            context={"size": len(data), "type": sniff.content_type},
        )
        await self._s.commit()
        return record

    async def get_metadata(self, org_id: str, user_id: str, file_id: str) -> File:
        await self._access.require_membership(org_id, user_id)
        record = await self._files.get(org_id, file_id)
        if record is None:
            raise NotFoundError("file not found")
        return record

    async def decrypt_filename(self, org_id: str, record: File) -> str:
        tmk = await self._tenant_key(org_id)
        (name,) = self._enc.decrypt_many(
            tmk, record.wrapped_dek, [record.filename_ciphertext],
            _file_aad(org_id, record.id),
        )
        return name.decode()

    async def issue_download_token(self, org_id: str, user_id: str,
                                   file_id: str) -> tuple[str, int]:
        record = await self.get_metadata(org_id, user_id, file_id)
        ttl = self._settings.download_token_ttl_seconds
        token = self._sec.issue_scoped_token(
            purpose="download", ttl_seconds=ttl,
            claims={"org": org_id, "fid": record.id, "sub": user_id},
        )
        return token, ttl

    async def download_with_token(self, token: str) -> DecryptedFile:
        try:
            payload = self._sec.decode_scoped_token(token, purpose="download")
        except jwt.PyJWTError as exc:
            raise InvalidTokenError("invalid download token") from exc
        org_id, file_id, user_id = payload["org"], payload["fid"], payload["sub"]
        record = await self._files.get(org_id, file_id)
        if record is None:
            raise NotFoundError("file not found")
        # Re-check the caller still has access at download time.
        await self._access.require_membership(org_id, user_id)

        tmk = await self._tenant_key(org_id)
        blob_ct = self._blobs.read(record.storage_key)
        data, name = self._enc.decrypt_many(
            tmk, record.wrapped_dek, [blob_ct, record.filename_ciphertext],
            _file_aad(org_id, record.id),
        )
        # Integrity verification against stored plaintext hash.
        if hashlib.sha256(data).hexdigest() != record.content_sha256:
            raise ValidationError("file integrity check failed")
        await self._audit.record(
            action=AuditAction.FILE_DOWNLOADED, org_id=org_id, actor_user_id=user_id,
            resource_type="file", resource_id=file_id,
        )
        await self._s.commit()
        return DecryptedFile(
            id=record.id, filename=name.decode(), content_type=record.content_type,
            size_bytes=record.size_bytes, data=data,
        )

    async def delete(self, org_id: str, user_id: str, file_id: str) -> None:
        record = await self._files.get(org_id, file_id)
        if record is None:
            raise NotFoundError("file not found")
        role = await self._access.require_membership(org_id, user_id)
        if not (role in (Role.OWNER, Role.ADMIN) or record.owner_id == user_id):
            raise ValidationError("insufficient permission to delete this file")
        await self._files.soft_delete(record)
        await self._audit.record(
            action=AuditAction.FILE_DELETED, org_id=org_id, actor_user_id=user_id,
            resource_type="file", resource_id=file_id,
        )
        await self._s.commit()

    async def list_files(self, org_id: str, user_id: str,
                         folder_id: str | None) -> list[tuple[File, str]]:
        await self._access.require_membership(org_id, user_id)
        tmk = await self._tenant_key(org_id)
        out = []
        for f in await self._files.list(org_id, folder_id=folder_id):
            (name,) = self._enc.decrypt_many(
                tmk, f.wrapped_dek, [f.filename_ciphertext], _file_aad(org_id, f.id)
            )
            out.append((f, name.decode()))
        return out
