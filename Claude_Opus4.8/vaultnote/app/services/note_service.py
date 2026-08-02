"""Notes & folders service: envelope-encrypted CRUD with hot-note caching."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cache import LRUCache
from app.core.compliance import AuditAction
from app.core.config import Settings
from app.core.encryption import EnvelopeEncryptor
from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.db.base import new_id, utcnow
from app.models.content import Folder, Note
from app.models.organization import Role
from app.repositories import (
    FolderRepository,
    NoteRepository,
    OrganizationRepository,
)
from app.services.access_service import AccessService
from app.services.audit_service import AuditService


@dataclass
class DecryptedNote:
    id: str
    title: str
    body: str
    folder_id: str | None
    owner_id: str
    version: int
    created_at: object
    updated_at: object


def _note_aad(org_id: str, note_id: str) -> bytes:
    # Bind ciphertext to tenant+object: a blob cannot be replayed under another
    # note or tenant (GCM AAD authenticated but not encrypted).
    return f"note:{org_id}:{note_id}".encode()


def _folder_aad(org_id: str, folder_id: str) -> bytes:
    return f"folder:{org_id}:{folder_id}".encode()


class NoteService:
    def __init__(self, session: AsyncSession, settings: Settings,
                 encryptor: EnvelopeEncryptor, note_cache: LRUCache) -> None:
        self._s = session
        self._settings = settings
        self._enc = encryptor
        self._cache = note_cache
        self._notes = NoteRepository(session)
        self._folders = FolderRepository(session)
        self._orgs = OrganizationRepository(session)
        self._access = AccessService(session)
        self._audit = AuditService(session, settings)

    async def _tenant_key(self, org_id: str) -> bytes:
        org = await self._orgs.get(org_id)
        if org is None:
            raise NotFoundError("organization not found")
        return org.wrapped_master_key

    # --- Folders -----------------------------------------------------------
    async def create_folder(self, org_id: str, user_id: str, *, name: str,
                            parent_id: str | None) -> Folder:
        await self._access.require_membership(org_id, user_id)
        if parent_id is not None:
            parent = await self._folders.get(org_id, parent_id)
            if parent is None:
                raise NotFoundError("parent folder not found")
        folder_id = new_id()
        tmk = await self._tenant_key(org_id)
        (name_ct,), wrapped = self._enc.encrypt_many(
            tmk, [name.encode()], _folder_aad(org_id, folder_id)
        )
        folder = Folder(
            id=folder_id, org_id=org_id, parent_id=parent_id, owner_id=user_id,
            name_ciphertext=name_ct, wrapped_dek=wrapped,
        )
        await self._folders.add(folder)
        await self._s.commit()
        return folder

    async def list_folders(self, org_id: str, user_id: str,
                           parent_id: str | None) -> list[tuple[Folder, str]]:
        await self._access.require_membership(org_id, user_id)
        tmk = await self._tenant_key(org_id)
        out: list[tuple[Folder, str]] = []
        for f in await self._folders.list(org_id, parent_id):
            (name,) = self._enc.decrypt_many(
                tmk, f.wrapped_dek, [f.name_ciphertext], _folder_aad(org_id, f.id)
            )
            out.append((f, name.decode()))
        return out

    # --- Notes -------------------------------------------------------------
    async def create_note(self, org_id: str, user_id: str, *, title: str,
                          body: str, folder_id: str | None) -> DecryptedNote:
        role = await self._access.require_membership(org_id, user_id)
        if role is Role.VIEWER:
            raise ValidationError("viewers cannot create notes")
        if folder_id is not None and await self._folders.get(org_id, folder_id) is None:
            raise NotFoundError("folder not found")

        note_id = new_id()
        tmk = await self._tenant_key(org_id)
        (title_ct, body_ct), wrapped = self._enc.encrypt_many(
            tmk, [title.encode(), body.encode()], _note_aad(org_id, note_id)
        )
        now = utcnow()
        note = Note(
            id=note_id, org_id=org_id, folder_id=folder_id, owner_id=user_id,
            title_ciphertext=title_ct, body_ciphertext=body_ct,
            wrapped_dek=wrapped, version=1, updated_at=now,
        )
        await self._notes.add(note)
        await self._audit.record(
            action=AuditAction.NOTE_CREATED, org_id=org_id, actor_user_id=user_id,
            resource_type="note", resource_id=note_id,
        )
        await self._s.commit()
        return self._to_dto(note, title, body)

    async def get_note(self, org_id: str, user_id: str, note_id: str) -> DecryptedNote:
        note = await self._notes.get(org_id, note_id)
        if note is None:
            raise NotFoundError("note not found")
        await self._access.require_note(org_id, user_id, note, "read")
        title, body = await self._decrypt_note(org_id, note)
        return self._to_dto(note, title, body)

    async def list_notes(self, org_id: str, user_id: str, *,
                         folder_id: str | None, limit: int, offset: int):
        await self._access.require_membership(org_id, user_id)
        tmk = await self._tenant_key(org_id)
        notes = await self._notes.list(
            org_id, folder_id=folder_id, limit=limit, offset=offset
        )
        summaries = []
        for n in notes:
            # Only titles are decrypted for the list view (less work, less exposure).
            (title,) = self._enc.decrypt_many(
                tmk, n.wrapped_dek, [n.title_ciphertext], _note_aad(org_id, n.id)
            )
            summaries.append((n, title.decode()))
        return summaries

    async def update_note(self, org_id: str, user_id: str, note_id: str, *,
                          title: str | None, body: str | None,
                          expected_version: int | None) -> DecryptedNote:
        note = await self._notes.get(org_id, note_id)
        if note is None:
            raise NotFoundError("note not found")
        await self._access.require_note(org_id, user_id, note, "write")
        if expected_version is not None and expected_version != note.version:
            raise ConflictError("note was modified by someone else")

        cur_title, cur_body = await self._decrypt_note(org_id, note)
        new_title = cur_title if title is None else title
        new_body = cur_body if body is None else body

        tmk = await self._tenant_key(org_id)
        (title_ct, body_ct), wrapped = self._enc.encrypt_many(
            tmk, [new_title.encode(), new_body.encode()], _note_aad(org_id, note.id)
        )
        note.title_ciphertext = title_ct
        note.body_ciphertext = body_ct
        note.wrapped_dek = wrapped
        note.version += 1
        note.updated_at = utcnow()
        self._cache.invalidate((org_id, note_id))
        await self._audit.record(
            action=AuditAction.NOTE_UPDATED, org_id=org_id, actor_user_id=user_id,
            resource_type="note", resource_id=note_id, context={"version": note.version},
        )
        await self._s.commit()
        return self._to_dto(note, new_title, new_body)

    async def delete_note(self, org_id: str, user_id: str, note_id: str) -> None:
        note = await self._notes.get(org_id, note_id)
        if note is None:
            raise NotFoundError("note not found")
        await self._access.require_note(org_id, user_id, note, "admin")
        await self._notes.soft_delete(note)  # retention window before purge
        self._cache.invalidate((org_id, note_id))
        await self._audit.record(
            action=AuditAction.NOTE_DELETED, org_id=org_id, actor_user_id=user_id,
            resource_type="note", resource_id=note_id,
        )
        await self._s.commit()

    # --- Helpers -----------------------------------------------------------
    async def _decrypt_note(self, org_id: str, note: Note) -> tuple[str, str]:
        cache_key = (org_id, note.id)
        cached = self._cache.get(cache_key)
        if cached is not None and cached[0] == note.version:
            return cached[1], cached[2]
        tmk = await self._tenant_key(org_id)
        title_b, body_b = self._enc.decrypt_many(
            tmk, note.wrapped_dek,
            [note.title_ciphertext, note.body_ciphertext],
            _note_aad(org_id, note.id),
        )
        title, body = title_b.decode(), body_b.decode()
        self._cache.put(cache_key, (note.version, title, body))
        return title, body

    @staticmethod
    def _to_dto(note: Note, title: str, body: str) -> DecryptedNote:
        return DecryptedNote(
            id=note.id, title=title, body=body, folder_id=note.folder_id,
            owner_id=note.owner_id, version=note.version,
            created_at=note.created_at, updated_at=note.updated_at,
        )
