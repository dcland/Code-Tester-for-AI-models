"""
Note and folder service - envelope encryption, CRUD, caching, key rotation.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import WrappedKey, encryption_service
from app.models.entities import Folder, Note, Organization
from app.repositories.repositories import FolderRepository, NoteRepository, OrganizationRepository
from app.utils.cache import note_cache
from app.utils.exceptions import NotFoundError


class NoteService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.notes = NoteRepository(session)
        self.folders = FolderRepository(session)
        self.orgs = OrganizationRepository(session)

    async def _tenant_kek(self, org_id: str) -> bytes:
        org = await self.orgs.get_by_id(org_id)
        if org is None:
            raise NotFoundError("Organization not found")
        return encryption_service.decrypt_kek(WrappedKey(org.kek_ciphertext, org.kek_nonce))

    # ---- Notes ----------------------------------------------------------
    async def create_note(
        self, org_id: str, workspace_id: str, user_id: str,
        title: str, content: str, folder_id: str | None = None,
    ) -> Note:
        kek = await self._tenant_kek(org_id)
        dek = encryption_service.generate_dek()
        title_ct, title_nonce = encryption_service.encrypt(title.encode(), dek)
        content_ct, content_nonce = encryption_service.encrypt(content.encode(), dek)
        wrapped_dek = encryption_service.wrap_dek(dek, kek)
        note = Note(
            workspace_id=workspace_id, organization_id=org_id, folder_id=folder_id,
            title_encrypted=title_ct, title_nonce=title_nonce,
            content_encrypted=content_ct, content_nonce=content_nonce,
            dek_ciphertext=wrapped_dek.ciphertext, dek_nonce=wrapped_dek.nonce,
            created_by=user_id,
        )
        await self.notes.create(note)
        return note

    async def get_note(self, org_id: str, note_id: str) -> dict:
        # Cache lookup is O(1)
        cache_key = f"note:{note_id}:{org_id}"
        cached = note_cache.get(cache_key)
        if cached is not None:
            return cached

        note = await self.notes.get_by_id_and_org(note_id, org_id)
        if note is None or note.deleted_at is not None:
            raise NotFoundError("Note not found")
        kek = await self._tenant_kek(org_id)
        dek = encryption_service.unwrap_dek(WrappedKey(note.dek_ciphertext, note.dek_nonce), kek)
        title = encryption_service.decrypt(note.title_encrypted, note.title_nonce, dek).decode()
        content = encryption_service.decrypt(note.content_encrypted, note.content_nonce, dek).decode()
        result = {
            "id": note.id, "title": title, "content": content,
            "folder_id": note.folder_id, "workspace_id": note.workspace_id,
            "version": note.version,
        }
        note_cache.put(cache_key, result)
        return result

    async def update_note(self, org_id: str, note_id: str, title: str | None, content: str | None) -> dict:
        note = await self.notes.get_by_id_and_org(note_id, org_id)
        if note is None or note.deleted_at is not None:
            raise NotFoundError("Note not found")
        kek = await self._tenant_kek(org_id)
        dek = encryption_service.unwrap_dek(WrappedKey(note.dek_ciphertext, note.dek_nonce), kek)
        if title is not None:
            ct, nonce = encryption_service.encrypt(title.encode(), dek)
            note.title_encrypted, note.title_nonce = ct, nonce
        if content is not None:
            ct, nonce = encryption_service.encrypt(content.encode(), dek)
            note.content_encrypted, note.content_nonce = ct, nonce
        note.version += 1
        await self.session.flush()
        note_cache.invalidate(f"note:{note_id}:{org_id}")
        return {"id": note.id, "version": note.version}

    async def list_notes(self, org_id: str, workspace_id: str) -> list[dict]:
        notes = await self.notes.list_active_by_workspace(workspace_id)
        kek = await self._tenant_kek(org_id)
        out: list[dict] = []
        for n in notes:
            dek = encryption_service.unwrap_dek(WrappedKey(n.dek_ciphertext, n.dek_nonce), kek)
            title = encryption_service.decrypt(n.title_encrypted, n.title_nonce, dek).decode()
            out.append({"id": n.id, "title": title, "folder_id": n.folder_id, "version": n.version})
        return out

    async def delete_note(self, org_id: str, note_id: str) -> None:
        note = await self.notes.get_by_id_and_org(note_id, org_id)
        if note is None:
            raise NotFoundError("Note not found")
        await self.notes.soft_delete(note)
        note_cache.invalidate(f"note:{note_id}:{org_id}")

    # ---- Folders ----------------------------------------------------------
    async def create_folder(self, org_id: str, workspace_id: str, name: str, parent_id: str | None) -> Folder:
        kek = await self._tenant_kek(org_id)
        dek = encryption_service.generate_dek()
        name_ct, name_nonce = encryption_service.encrypt(name.encode(), dek)
        wrapped = encryption_service.wrap_dek(dek, kek)
        folder = Folder(
            workspace_id=workspace_id, organization_id=org_id, parent_id=parent_id,
            name_encrypted=name_ct, name_nonce=name_nonce,
            dek_ciphertext=wrapped.ciphertext, dek_nonce=wrapped.nonce,
        )
        await self.folders.create(folder)
        return folder

    async def list_folders(self, org_id: str, workspace_id: str, parent_id: str | None) -> list[dict]:
        folders = await self.folders.list_children(parent_id, workspace_id)
        kek = await self._tenant_kek(org_id)
        out: list[dict] = []
        for f in folders:
            dek = encryption_service.unwrap_dek(WrappedKey(f.dek_ciphertext, f.dek_nonce), kek)
            name = encryption_service.decrypt(f.name_encrypted, f.name_nonce, dek).decode()
            out.append({"id": f.id, "name": name, "parent_id": f.parent_id})
        return out

    # ---- Key rotation -----------------------------------------------------
    async def rotate_tenant_key(self, org_id: str) -> int:
        """Rotate tenant KEK and re-wrap all DEKs. Returns count of re-wrapped items."""
        org = await self.orgs.get_by_id(org_id)
        if org is None:
            raise NotFoundError("Organization not found")
        old_kek = encryption_service.decrypt_kek(WrappedKey(org.kek_ciphertext, org.kek_nonce))
        new_kek = encryption_service.generate_tenant_kek()

        count = 0
        # Re-wrap notes
        notes = await self.notes.list_active_by_workspace_all_org(org_id) if hasattr(self.notes, 'list_active_by_workspace_all_org') else []
        for n in await self._all_notes_for_org(org_id):
            wrapped = encryption_service.rotate_dek(WrappedKey(n.dek_ciphertext, n.dek_nonce), old_kek, new_kek)
            n.dek_ciphertext, n.dek_nonce = wrapped.ciphertext, wrapped.nonce
            count += 1
        for f in await self._all_folders_for_org(org_id):
            wrapped = encryption_service.rotate_dek(WrappedKey(f.dek_ciphertext, f.dek_nonce), old_kek, new_kek)
            f.dek_ciphertext, f.dek_nonce = wrapped.ciphertext, wrapped.nonce
            count += 1

        new_wrapped = encryption_service.encrypt_kek(new_kek)
        org.kek_ciphertext, org.kek_nonce = new_wrapped.ciphertext, new_wrapped.nonce
        await self.session.flush()
        note_cache.clear()
        return count

    async def _all_notes_for_org(self, org_id: str) -> list[Note]:
        from sqlalchemy import select
        result = await self.session.execute(select(Note).where(Note.organization_id == org_id, Note.deleted_at.is_(None)))
        return list(result.scalars().all())

    async def _all_folders_for_org(self, org_id: str) -> list[Folder]:
        from sqlalchemy import select
        result = await self.session.execute(select(Folder).where(Folder.organization_id == org_id))
        return list(result.scalars().all())
