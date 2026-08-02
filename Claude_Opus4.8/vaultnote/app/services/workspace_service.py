"""Workspace (tenant) membership management."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance import AuditAction
from app.core.config import Settings
from app.core.exceptions import (
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from app.models.organization import Membership, Role
from app.repositories import (
    MembershipRepository,
    OrganizationRepository,
    UserRepository,
)
from app.services.audit_service import AuditService
from app.services.billing_service import PLAN_LIMITS


class WorkspaceService:
    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._s = session
        self._orgs = OrganizationRepository(session)
        self._members = MembershipRepository(session)
        self._users = UserRepository(session)
        self._audit = AuditService(session, settings)

    async def _require_role(self, org_id: str, user_id: str, minimum: Role) -> Role:
        role = await self._members.get_role(org_id, user_id)
        if role is None:
            raise AuthorizationError("not a member of this organization")
        if not role.at_least(minimum):
            raise AuthorizationError("insufficient role for this action")
        return role

    async def list_my_orgs(self, user_id: str) -> list[tuple[object, Role]]:
        out = []
        for m in await self._members.list_for_user(user_id):
            org = await self._orgs.get(m.org_id)
            if org is not None:
                out.append((org, Role(m.role)))
        return out

    async def list_members(self, org_id: str, user_id: str) -> list[Membership]:
        await self._require_role(org_id, user_id, Role.VIEWER)
        return await self._members.list_for_org(org_id)

    async def invite_member(self, org_id: str, actor_id: str, *, email: str,
                            role: str) -> Membership:
        await self._require_role(org_id, actor_id, Role.ADMIN)
        if role == Role.OWNER:
            raise ValidationError("cannot invite a second owner; transfer instead")

        # Seat limit enforcement (billing).
        org = await self._orgs.get(org_id)
        if org is None:
            raise NotFoundError("organization not found")
        current = await self._members.count_for_org(org_id)
        if current >= PLAN_LIMITS[org.plan].max_seats:
            raise ValidationError("seat limit reached for current plan")

        user = await self._users.get_by_email(email)
        if user is None:
            # We do not create accounts implicitly; invite requires an existing
            # user. We also avoid revealing (non-)existence beyond this action.
            raise NotFoundError("no user with that email to invite")
        if await self._members.get(org_id, user.id) is not None:
            raise ConflictError("user is already a member")

        membership = await self._members.add(
            Membership(org_id=org_id, user_id=user.id, role=Role(role))
        )
        await self._audit.record(
            action=AuditAction.MEMBER_INVITED, org_id=org_id, actor_user_id=actor_id,
            resource_type="user", resource_id=user.id, context={"role": role},
        )
        await self._s.commit()
        return membership

    async def change_role(self, org_id: str, actor_id: str, target_user_id: str,
                          new_role: str) -> None:
        await self._require_role(org_id, actor_id, Role.ADMIN)
        membership = await self._members.get(org_id, target_user_id)
        if membership is None:
            raise NotFoundError("member not found")
        if membership.role == Role.OWNER:
            raise ValidationError("cannot change the owner's role")
        if new_role == Role.OWNER:
            raise ValidationError("ownership transfer is a separate operation")
        membership.role = new_role
        await self._audit.record(
            action=AuditAction.MEMBER_ROLE_CHANGED, org_id=org_id,
            actor_user_id=actor_id, resource_type="user", resource_id=target_user_id,
            context={"role": new_role},
        )
        await self._s.commit()

    async def remove_member(self, org_id: str, actor_id: str,
                            target_user_id: str) -> None:
        await self._require_role(org_id, actor_id, Role.ADMIN)
        membership = await self._members.get(org_id, target_user_id)
        if membership is None:
            raise NotFoundError("member not found")
        if membership.role == Role.OWNER:
            raise ValidationError("cannot remove the organization owner")
        await self._members.remove(org_id, target_user_id)
        await self._audit.record(
            action=AuditAction.MEMBER_REMOVED, org_id=org_id, actor_user_id=actor_id,
            resource_type="user", resource_id=target_user_id,
        )
        await self._s.commit()
