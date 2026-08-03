"""
Concrete repositories for each entity.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import (
    ConsentRecord, DownloadToken, FileAsset, Folder, Invoice, Membership,
    Note, NoteOperation, Organization, PresenceState, RefreshToken, ShareGrant,
    ShareLink, Subscription, UsageRecord, User, Workspace,
)
from app.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    model = User

    async def get_by_email(self, email: str) -> User | None:
        result = await self.session.execute(select(User).where(User.email == email.lower()))
        return result.scalar_one_or_none()


class OrganizationRepository(BaseRepository[Organization]):
    model = Organization

    async def get_by_slug(self, slug: str) -> Organization | None:
        result = await self.session.execute(select(Organization).where(Organization.slug == slug))
        return result.scalar_one_or_none()


class MembershipRepository(BaseRepository[Membership]):
    model = Membership

    async def get_membership(self, user_id: str, org_id: str) -> Membership | None:
        result = await self.session.execute(
            select(Membership).where(
                Membership.user_id == user_id, Membership.organization_id == org_id
            )
        )
        return result.scalar_one_or_none()

    async def list_user_orgs(self, user_id: str) -> list[Membership]:
        result = await self.session.execute(select(Membership).where(Membership.user_id == user_id))
        return list(result.scalars().all())

    async def list_org_members(self, org_id: str) -> list[Membership]:
        result = await self.session.execute(select(Membership).where(Membership.organization_id == org_id))
        return list(result.scalars().all())


class RefreshTokenRepository(BaseRepository[RefreshToken]):
    model = RefreshToken

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        result = await self.session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        return result.scalar_one_or_none()

    async def revoke_all_for_user(self, user_id: str) -> None:
        result = await self.session.execute(
            select(RefreshToken).where(RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))
        )
        for t in result.scalars().all():
            t.revoked = True
        await self.session.flush()


class WorkspaceRepository(BaseRepository[Workspace]):
    model = Workspace


class FolderRepository(BaseRepository[Folder]):
    model = Folder

    async def list_children(self, parent_id: str | None, workspace_id: str) -> list[Folder]:
        q = select(Folder).where(Folder.workspace_id == workspace_id)
        if parent_id is None:
            q = q.where(Folder.parent_id.is_(None))
        else:
            q = q.where(Folder.parent_id == parent_id)
        result = await self.session.execute(q)
        return list(result.scalars().all())


class NoteRepository(BaseRepository[Note]):
    model = Note

    async def list_active_by_workspace(self, workspace_id: str) -> list[Note]:
        result = await self.session.execute(
            select(Note).where(Note.workspace_id == workspace_id, Note.deleted_at.is_(None))
        )
        return list(result.scalars().all())

    async def soft_delete(self, note: Note) -> None:
        note.deleted_at = datetime.now(timezone.utc)
        await self.session.flush()


class FileRepository(BaseRepository[FileAsset]):
    model = FileAsset


class ShareGrantRepository(BaseRepository[ShareGrant]):
    model = ShareGrant

    async def get_grant(self, resource_type: str, resource_id: str, user_id: str) -> ShareGrant | None:
        result = await self.session.execute(
            select(ShareGrant).where(
                ShareGrant.resource_type == resource_type,
                ShareGrant.resource_id == resource_id,
                ShareGrant.grantee_user_id == user_id,
            )
        )
        return result.scalar_one_or_none()


class ShareLinkRepository(BaseRepository[ShareLink]):
    model = ShareLink

    async def get_by_hash(self, token_hash: str) -> ShareLink | None:
        result = await self.session.execute(
            select(ShareLink).where(ShareLink.token_hash == token_hash)
        )
        return result.scalar_one_or_none()


class SubscriptionRepository(BaseRepository[Subscription]):
    model = Subscription

    async def get_by_org(self, org_id: str) -> Subscription | None:
        result = await self.session.execute(
            select(Subscription).where(Subscription.organization_id == org_id)
        )
        return result.scalar_one_or_none()


class UsageRepository(BaseRepository[UsageRecord]):
    model = UsageRecord

    async def get_or_create_today(self, org_id: str, date: str) -> UsageRecord:
        result = await self.session.execute(
            select(UsageRecord).where(UsageRecord.organization_id == org_id, UsageRecord.date == date)
        )
        rec = result.scalar_one_or_none()
        if rec is None:
            rec = UsageRecord(organization_id=org_id, date=date)
            self.session.add(rec)
            await self.session.flush()
        return rec


class InvoiceRepository(BaseRepository[Invoice]):
    model = Invoice


class ConsentRepository(BaseRepository[ConsentRecord]):
    model = ConsentRecord

    async def list_for_user(self, user_id: str) -> list[ConsentRecord]:
        result = await self.session.execute(select(ConsentRecord).where(ConsentRecord.user_id == user_id))
        return list(result.scalars().all())


class DownloadTokenRepository(BaseRepository[DownloadToken]):
    model = DownloadToken

    async def get_by_hash(self, token_hash: str) -> DownloadToken | None:
        result = await self.session.execute(
            select(DownloadToken).where(DownloadToken.token_hash == token_hash)
        )
        return result.scalar_one_or_none()


class PresenceRepository(BaseRepository[PresenceState]):
    model = PresenceState

    async def list_for_note(self, note_id: str) -> list[PresenceState]:
        result = await self.session.execute(select(PresenceState).where(PresenceState.note_id == note_id))
        return list(result.scalars().all())


class NoteOperationRepository(BaseRepository[NoteOperation]):
    model = NoteOperation

    async def max_lamport(self, note_id: str) -> int:
        result = await self.session.execute(
            select(NoteOperation.lamport)
            .where(NoteOperation.note_id == note_id)
            .order_by(NoteOperation.lamport.desc())
            .limit(1)
        )
        val = result.scalar_one_or_none()
        return int(val) if val is not None else 0

    async def list_operations(self, note_id: str) -> list[NoteOperation]:
        result = await self.session.execute(
            select(NoteOperation).where(NoteOperation.note_id == note_id).order_by(NoteOperation.lamport)
        )
        return list(result.scalars().all())
