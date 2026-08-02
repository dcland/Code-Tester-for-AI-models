"""Share and share-link repositories."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.models.sharing import Share, ShareLink


class ShareRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def upsert(self, org_id: str, resource_type: str, resource_id: str,
                     grantee_user_id: str, permission: str, created_by: str) -> Share:
        existing = await self.get(resource_type, resource_id, grantee_user_id)
        if existing:
            existing.permission = permission
            await self._s.flush()
            return existing
        row = Share(
            org_id=org_id, resource_type=resource_type, resource_id=resource_id,
            grantee_user_id=grantee_user_id, permission=permission, created_by=created_by,
        )
        self._s.add(row)
        await self._s.flush()
        return row

    async def get(self, resource_type: str, resource_id: str,
                  grantee_user_id: str) -> Share | None:
        stmt = select(Share).where(
            Share.resource_type == resource_type,
            Share.resource_id == resource_id,
            Share.grantee_user_id == grantee_user_id,
        )
        return (await self._s.execute(stmt)).scalar_one_or_none()

    async def list_for_resource(self, resource_type: str,
                                resource_id: str) -> list[Share]:
        stmt = select(Share).where(
            Share.resource_type == resource_type, Share.resource_id == resource_id
        )
        return list((await self._s.execute(stmt)).scalars())


class ShareLinkRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, link: ShareLink) -> ShareLink:
        self._s.add(link)
        await self._s.flush()
        return link

    async def get_by_token_hash(self, token_hash: str) -> ShareLink | None:
        stmt = select(ShareLink).where(
            ShareLink.token_hash == token_hash, ShareLink.revoked_at.is_(None)
        )
        return (await self._s.execute(stmt)).scalar_one_or_none()

    async def is_valid(self, link: ShareLink) -> bool:
        if link.revoked_at is not None:
            return False
        if link.expires_at is not None and link.expires_at <= utcnow():
            return False
        return True
