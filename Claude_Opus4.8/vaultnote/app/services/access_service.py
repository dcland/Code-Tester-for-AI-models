"""Centralized authorization (least privilege, OWASP A01 broken access control).

Effective permission on a resource is the maximum of:
  * the caller's tenant role (owner/admin get admin over the workspace),
  * resource ownership (owner gets admin on their own resource),
  * explicit shares on the resource or its containing folder,
capped by role ceilings (a viewer can never exceed read).

Every resource lookup is tenant-scoped, so a caller can only ever reference
objects inside their active organization.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthorizationError, NotFoundError
from app.models.organization import Role
from app.repositories import (
    MembershipRepository,
    NoteRepository,
    ShareRepository,
)

PERM_LEVELS = {"read": 1, "write": 2, "admin": 3}
LEVEL_NAMES = {1: "read", 2: "write", 3: "admin"}


class AccessService:
    def __init__(self, session: AsyncSession) -> None:
        self._members = MembershipRepository(session)
        self._shares = ShareRepository(session)
        self._notes = NoteRepository(session)

    async def require_membership(self, org_id: str, user_id: str) -> Role:
        role = await self._members.get_role(org_id, user_id)
        if role is None:
            # Do not distinguish "no such org" from "not a member" — both 403.
            raise AuthorizationError("not a member of this organization")
        return role

    async def _share_level(self, resource_type: str, resource_id: str,
                           user_id: str, folder_id: str | None) -> int:
        level = 0
        direct = await self._shares.get(resource_type, resource_id, user_id)
        if direct:
            level = max(level, PERM_LEVELS.get(direct.permission, 0))
        if folder_id:
            inherited = await self._shares.get("folder", folder_id, user_id)
            if inherited:
                level = max(level, PERM_LEVELS.get(inherited.permission, 0))
        return level

    def _combine(self, role: Role, is_owner: bool, share_level: int) -> int:
        level = 0
        if role in (Role.OWNER, Role.ADMIN):
            level = PERM_LEVELS["admin"]
        if is_owner:
            level = PERM_LEVELS["admin"]
        level = max(level, share_level)
        if role is Role.VIEWER:
            level = min(level, PERM_LEVELS["read"])  # role ceiling
        return level

    async def note_permission(self, org_id: str, user_id: str, note) -> int:
        role = await self.require_membership(org_id, user_id)
        share_level = await self._share_level(
            "note", note.id, user_id, note.folder_id
        )
        return self._combine(role, note.owner_id == user_id, share_level)

    async def require_note(self, org_id: str, user_id: str, note,
                           minimum: str) -> None:
        have = await self.note_permission(org_id, user_id, note)
        if have < PERM_LEVELS[minimum]:
            raise AuthorizationError(
                f"requires {minimum} permission on this note"
            )

    async def folder_permission(self, org_id: str, user_id: str, folder) -> int:
        role = await self.require_membership(org_id, user_id)
        share_level = await self._share_level(
            "folder", folder.id, user_id, folder.parent_id
        )
        return self._combine(role, folder.owner_id == user_id, share_level)
