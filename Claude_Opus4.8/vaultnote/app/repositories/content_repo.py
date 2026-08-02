"""Folder, note and file repositories. All queries are tenant-scoped by org_id."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.models.content import File, Folder, Note


class FolderRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, folder: Folder) -> Folder:
        self._s.add(folder)
        await self._s.flush()
        return folder

    async def get(self, org_id: str, folder_id: str) -> Folder | None:
        # Tenant isolation: org_id is part of the predicate, not just the id.
        stmt = select(Folder).where(
            Folder.id == folder_id,
            Folder.org_id == org_id,
            Folder.deleted_at.is_(None),
        )
        return (await self._s.execute(stmt)).scalar_one_or_none()

    async def list(self, org_id: str, parent_id: str | None) -> list[Folder]:
        stmt = select(Folder).where(
            Folder.org_id == org_id,
            Folder.parent_id.is_(parent_id) if parent_id is None
            else Folder.parent_id == parent_id,
            Folder.deleted_at.is_(None),
        ).order_by(Folder.created_at)
        return list((await self._s.execute(stmt)).scalars())


class NoteRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, note: Note) -> Note:
        self._s.add(note)
        await self._s.flush()
        return note

    async def get(self, org_id: str, note_id: str) -> Note | None:
        stmt = select(Note).where(
            Note.id == note_id,
            Note.org_id == org_id,
            Note.deleted_at.is_(None),
        )
        return (await self._s.execute(stmt)).scalar_one_or_none()

    async def list(self, org_id: str, *, folder_id: str | None = None,
                   limit: int = 100, offset: int = 0) -> list[Note]:
        stmt = select(Note).where(Note.org_id == org_id, Note.deleted_at.is_(None))
        if folder_id is not None:
            stmt = stmt.where(Note.folder_id == folder_id)
        stmt = stmt.order_by(Note.updated_at.desc()).limit(limit).offset(offset)
        return list((await self._s.execute(stmt)).scalars())

    async def soft_delete(self, note: Note) -> None:
        note.deleted_at = utcnow()
        await self._s.flush()

    async def count(self, org_id: str) -> int:
        stmt = select(func.count()).select_from(Note).where(
            Note.org_id == org_id, Note.deleted_at.is_(None)
        )
        return int((await self._s.execute(stmt)).scalar_one())


class FileRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, file: File) -> File:
        self._s.add(file)
        await self._s.flush()
        return file

    async def get(self, org_id: str, file_id: str) -> File | None:
        stmt = select(File).where(
            File.id == file_id,
            File.org_id == org_id,
            File.deleted_at.is_(None),
        )
        return (await self._s.execute(stmt)).scalar_one_or_none()

    async def list(self, org_id: str, *, folder_id: str | None = None) -> list[File]:
        stmt = select(File).where(File.org_id == org_id, File.deleted_at.is_(None))
        if folder_id is not None:
            stmt = stmt.where(File.folder_id == folder_id)
        stmt = stmt.order_by(File.created_at.desc())
        return list((await self._s.execute(stmt)).scalars())

    async def soft_delete(self, file: File) -> None:
        file.deleted_at = utcnow()
        await self._s.flush()

    async def total_storage(self, org_id: str) -> int:
        stmt = select(func.coalesce(func.sum(File.size_bytes), 0)).where(
            File.org_id == org_id, File.deleted_at.is_(None)
        )
        return int((await self._s.execute(stmt)).scalar_one())

    async def count(self, org_id: str) -> int:
        stmt = select(func.count()).select_from(File).where(
            File.org_id == org_id, File.deleted_at.is_(None)
        )
        return int((await self._s.execute(stmt)).scalar_one())
