"""Fine-grained sharing and public share links."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance import AuditAction
from app.core.config import Settings
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationError,
)
from app.core.security import SecurityService
from app.db.base import utcnow
from app.models.sharing import ShareLink
from app.repositories import (
    MembershipRepository,
    NoteRepository,
    ShareLinkRepository,
    ShareRepository,
)
from app.services.access_service import PERM_LEVELS, AccessService
from app.services.audit_service import AuditService


@dataclass
class ShareLinkIssued:
    token: str
    permission: str
    expires_at: object


class SharingService:
    def __init__(self, session: AsyncSession, settings: Settings,
                 security: SecurityService) -> None:
        self._s = session
        self._sec = security
        self._shares = ShareRepository(session)
        self._links = ShareLinkRepository(session)
        self._notes = NoteRepository(session)
        self._members = MembershipRepository(session)
        self._access = AccessService(session)
        self._audit = AuditService(session, settings)

    async def share_note_with_user(self, org_id: str, actor_id: str, note_id: str,
                                   grantee_user_id: str, permission: str) -> None:
        note = await self._notes.get(org_id, note_id)
        if note is None:
            raise NotFoundError("note not found")
        # Only someone with admin on the note may share it.
        await self._access.require_note(org_id, actor_id, note, "admin")
        # Grantee must be a member of the same tenant (no cross-tenant shares).
        if await self._members.get_role(org_id, grantee_user_id) is None:
            raise ValidationError("grantee is not a member of this organization")
        if permission not in PERM_LEVELS:
            raise ValidationError("invalid permission")
        await self._shares.upsert(
            org_id, "note", note_id, grantee_user_id, permission, actor_id
        )
        await self._audit.record(
            action=AuditAction.NOTE_SHARED, org_id=org_id, actor_user_id=actor_id,
            resource_type="note", resource_id=note_id,
            context={"permission": permission},
        )
        await self._s.commit()

    async def create_share_link(self, org_id: str, actor_id: str, note_id: str, *,
                                permission: str, password: str | None,
                                expires_in_seconds: int | None) -> ShareLinkIssued:
        note = await self._notes.get(org_id, note_id)
        if note is None:
            raise NotFoundError("note not found")
        await self._access.require_note(org_id, actor_id, note, "admin")

        raw_token = self._sec.generate_opaque_secret()
        expires_at = (
            utcnow() + timedelta(seconds=expires_in_seconds)
            if expires_in_seconds else None
        )
        link = ShareLink(
            org_id=org_id, resource_type="note", resource_id=note_id,
            token_hash=self._sec.hash_token(raw_token),
            password_hash=self._sec.hash_password(password) if password else None,
            permission=permission, expires_at=expires_at, created_by=actor_id,
        )
        await self._links.add(link)
        await self._audit.record(
            action=AuditAction.SHARE_LINK_CREATED, org_id=org_id, actor_user_id=actor_id,
            resource_type="note", resource_id=note_id,
            context={"has_password": bool(password), "expires": bool(expires_at)},
        )
        await self._s.commit()
        return ShareLinkIssued(raw_token, permission, expires_at)

    async def resolve_share_link(self, raw_token: str,
                                 password: str | None) -> tuple[str, str, str]:
        """Return (org_id, resource_type, resource_id) if the link is valid.

        The link password is verified in constant time via Argon2. Invalid
        password and missing link yield the same error to avoid oracles.
        """
        link = await self._links.get_by_token_hash(self._sec.hash_token(raw_token))
        if link is None or not await self._links.is_valid(link):
            raise NotFoundError("share link not found or expired")
        if link.password_hash is not None:
            if not password or not self._sec.verify_password(password, link.password_hash):
                raise AuthenticationError("invalid share link password")
        return link.org_id, link.resource_type, link.resource_id
