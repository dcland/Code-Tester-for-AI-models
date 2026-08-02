"""Organization and membership repositories."""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Membership, Organization, Role


class OrganizationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, org: Organization) -> Organization:
        self._s.add(org)
        await self._s.flush()
        return org

    async def get(self, org_id: str) -> Organization | None:
        org = await self._s.get(Organization, org_id)
        if org is None or org.deleted_at is not None:
            return None
        return org

    async def get_including_deleted(self, org_id: str) -> Organization | None:
        return await self._s.get(Organization, org_id)


class MembershipRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, membership: Membership) -> Membership:
        self._s.add(membership)
        await self._s.flush()
        return membership

    async def get(self, org_id: str, user_id: str) -> Membership | None:
        stmt = select(Membership).where(
            Membership.org_id == org_id, Membership.user_id == user_id
        )
        return (await self._s.execute(stmt)).scalar_one_or_none()

    async def get_role(self, org_id: str, user_id: str) -> Role | None:
        m = await self.get(org_id, user_id)
        return Role(m.role) if m else None

    async def list_for_org(self, org_id: str) -> list[Membership]:
        stmt = select(Membership).where(Membership.org_id == org_id)
        return list((await self._s.execute(stmt)).scalars())

    async def list_for_user(self, user_id: str) -> list[Membership]:
        stmt = select(Membership).where(Membership.user_id == user_id)
        return list((await self._s.execute(stmt)).scalars())

    async def count_for_org(self, org_id: str) -> int:
        from sqlalchemy import func

        stmt = select(func.count()).select_from(Membership).where(
            Membership.org_id == org_id
        )
        return int((await self._s.execute(stmt)).scalar_one())

    async def remove(self, org_id: str, user_id: str) -> None:
        await self._s.execute(
            delete(Membership).where(
                Membership.org_id == org_id, Membership.user_id == user_id
            )
        )
