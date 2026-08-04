"""
Repository layer - data access with parameterized queries (SQL-injection safe).
"""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import Base


class BaseRepository[ModelT: Base]:
    """Generic repository with tenant scoping."""

    model: type[ModelT]

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(self, id_: str) -> ModelT | None:
        result = await self.session.execute(select(self.model).where(self.model.id == id_))  # type: ignore[attr-defined]
        return result.scalar_one_or_none()

    async def get_by_id_and_org(self, id_: str, org_id: str) -> ModelT | None:
        result = await self.session.execute(
            select(self.model).where(
                self.model.id == id_,  # type: ignore[attr-defined]
                self.model.organization_id == org_id,  # type: ignore[attr-defined]
            )
        )
        return result.scalar_one_or_none()

    async def list_by_org(self, org_id: str, limit: int = 100, offset: int = 0) -> list[ModelT]:
        result = await self.session.execute(
            select(self.model)
            .where(self.model.organization_id == org_id)  # type: ignore[attr-defined]
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def create(self, obj: ModelT) -> ModelT:
        self.session.add(obj)
        await self.session.flush()
        return obj

    async def delete(self, obj: ModelT) -> None:
        await self.session.delete(obj)
        await self.session.flush()

    async def count_by_org(self, org_id: str) -> int:
        result = await self.session.execute(
            select(func.count()).select_from(self.model).where(
                self.model.organization_id == org_id  # type: ignore[attr-defined]
            )
        )
        return int(result.scalar_one())
