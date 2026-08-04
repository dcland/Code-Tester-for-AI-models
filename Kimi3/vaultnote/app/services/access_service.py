"""
Centralized resource-level authorization (OWASP A01 - Broken Access Control).

Effective permission on a note is the maximum of:
  * the caller's tenant role (owner/admin have full control),
  * resource ownership (the creator has admin on their own resource),
  * explicit share grants on the note or its containing folder,
capped by role ceilings (a VIEWER can never exceed read, even with a
write/admin grant).

Every lookup is tenant-scoped: a caller can only ever reference objects
inside their active organization, and workspace path parameters are always
validated against the active tenant.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import Folder, Note, Permission, Role, Workspace
from app.repositories.repositories import (
    FolderRepository,
    MembershipRepository,
    NoteRepository,
    ShareGrantRepository,
    WorkspaceRepository,
)
from app.utils.exceptions import AuthorizationError, NotFoundError, ValidationError

PERM_LEVELS = {Permission.READ: 1, Permission.WRITE: 2, Permission.ADMIN: 3}
READ, WRITE, ADMIN = Permission.READ, Permission.WRITE, Permission.ADMIN


class AccessService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.members = MembershipRepository(session)
        self.grants = ShareGrantRepository(session)
        self.notes = NoteRepository(session)
        self.folders = FolderRepository(session)
        self.workspaces = WorkspaceRepository(session)

    # ---- Tenant & workspace binding ----------------------------------------
    async def require_membership(self, org_id: str, user_id: str) -> Role:
        membership = await self.members.get_membership(user_id, org_id)
        if membership is None:
            # Do not distinguish "no such org" from "not a member".
            raise AuthorizationError("Not a member of this organization")
        return membership.role

    async def get_workspace(self, org_id: str, workspace_id: str) -> Workspace:
        """Load a workspace, enforcing that it belongs to the active tenant."""
        ws = await self.workspaces.get_by_id(workspace_id)
        if ws is None or ws.organization_id != org_id:
            raise NotFoundError("Workspace not found")
        return ws

    # ---- Resource loading (tenant-scoped) -----------------------------------
    async def get_note(self, org_id: str, note_id: str) -> Note:
        note = await self.notes.get_by_id_and_org(note_id, org_id)
        if note is None or note.deleted_at is not None:
            raise NotFoundError("Note not found")
        return note

    async def get_folder(self, org_id: str, folder_id: str) -> Folder:
        folder = await self.folders.get_by_id_and_org(folder_id, org_id)
        if folder is None:
            raise NotFoundError("Folder not found")
        return folder

    # ---- Permission resolution ----------------------------------------------
    async def _share_level(
        self, resource_type: str, resource_id: str, user_id: str, folder_id: str | None
    ) -> int:
        level = 0
        direct = await self.grants.get_grant(resource_type, resource_id, user_id)
        if direct is not None:
            level = max(level, PERM_LEVELS.get(direct.permission, 0))
        if folder_id:
            inherited = await self.grants.get_grant("folder", folder_id, user_id)
            if inherited is not None:
                level = max(level, PERM_LEVELS.get(inherited.permission, 0))
        return level

    @staticmethod
    def _combine(role: Role, is_owner: bool, share_level: int) -> int:
        level = 0
        if role in (Role.OWNER, Role.ADMIN):
            level = PERM_LEVELS[Permission.ADMIN]
        if is_owner:
            level = PERM_LEVELS[Permission.ADMIN]
        level = max(level, share_level)
        if role is Role.VIEWER:
            level = min(level, PERM_LEVELS[Permission.READ])  # role ceiling
        return level

    async def note_level(self, org_id: str, user_id: str, note: Note) -> int:
        role = await self.require_membership(org_id, user_id)
        share_level = await self._share_level("note", note.id, user_id, note.folder_id)
        return self._combine(role, note.created_by == user_id, share_level)

    async def require_note(
        self, org_id: str, user_id: str, note: Note, minimum: Permission
    ) -> None:
        have = await self.note_level(org_id, user_id, note)
        if have < PERM_LEVELS[minimum]:
            raise AuthorizationError(f"Requires {minimum.value} permission on this note")

    # ---- Sharing guards -------------------------------------------------------
    async def require_grantee_member(self, org_id: str, grantee_user_id: str) -> None:
        """A share grant may only target a member of the SAME organization."""
        if await self.members.get_membership(grantee_user_id, org_id) is None:
            raise ValidationError("Grantee is not a member of this organization")
