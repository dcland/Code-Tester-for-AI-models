"""Append-only audit repository (tamper-evident hash chain)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog


class AuditRepository:
    """Exposes append + read only. There is deliberately no update/delete API."""

    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def last_hash(self, org_id: str | None) -> str | None:
        stmt = (
            select(AuditLog.entry_hash)
            .where(AuditLog.org_id.is_(org_id) if org_id is None
                   else AuditLog.org_id == org_id)
            .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
            .limit(1)
        )
        return (await self._s.execute(stmt)).scalar_one_or_none()

    async def append(self, entry: AuditLog) -> AuditLog:
        self._s.add(entry)
        await self._s.flush()
        return entry

    async def list_for_org(self, org_id: str, limit: int = 100,
                           offset: int = 0) -> list[AuditLog]:
        stmt = (
            select(AuditLog)
            .where(AuditLog.org_id == org_id)
            .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list((await self._s.execute(stmt)).scalars())

    async def all_for_org_chrono(self, org_id: str) -> list[AuditLog]:
        stmt = (
            select(AuditLog)
            .where(AuditLog.org_id == org_id)
            .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
        )
        return list((await self._s.execute(stmt)).scalars())
