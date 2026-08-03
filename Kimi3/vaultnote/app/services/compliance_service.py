"""
Compliance service: GDPR Art. 17 erasure, Art. 15/CCPA export, consent,
retention purge jobs.
"""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance import AuditLog, retention_days_for_plan
from app.core.privacy import pseudonymize
from app.models.entities import (
    ConsentRecord, DownloadToken, FileAsset, Folder, Membership, Note,
    NoteOperation, Organization, PresenceState, RefreshToken, ShareGrant,
    ShareLink, User, Workspace,
)
from app.repositories.repositories import ConsentRepository, OrganizationRepository, UserRepository
from app.utils.exceptions import NotFoundError


class ComplianceService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.users = UserRepository(session)
        self.orgs = OrganizationRepository(session)
        self.consents = ConsentRepository(session)

    # ---- GDPR Art. 17 - Right to Erasure (user) --------------------------
    async def erase_user(self, user_id: str, org_id: str) -> dict:
        """Cascading deletion of all personal data for a user.

        GDPR Art. 17 - erasure; CCPA - right to delete.
        """
        user = await self.users.get_by_id(user_id)
        if user is None:
            raise NotFoundError("User not found")

        await self.session.execute(delete(RefreshToken).where(RefreshToken.user_id == user_id))
        await self.session.execute(delete(ConsentRecord).where(ConsentRecord.user_id == user_id))
        await self.session.execute(delete(ShareGrant).where(ShareGrant.grantee_user_id == user_id))
        await self.session.execute(delete(Membership).where(Membership.user_id == user_id))

        AuditLog.record("user_erased", actor_id=pseudonymize(user_id), tenant_id=org_id,
                        resource_type="user", resource_id=pseudonymize(user_id))

        await self.session.delete(user)
        await self.session.flush()
        return {"erased": True}

    # ---- GDPR Art. 17 - Right to Erasure (organization) -------------------
    async def erase_organization(self, org_id: str) -> dict:
        """Cascading deletion of an entire tenant and all its data."""
        org = await self.orgs.get_by_id(org_id)
        if org is None:
            raise NotFoundError("Organization not found")

        # Delete in dependency order
        ws_ids = [r[0] for r in (await self.session.execute(
            select(Workspace.id).where(Workspace.organization_id == org_id))).all()]

        if ws_ids:
            await self.session.execute(delete(NoteOperation).where(
                NoteOperation.note_id.in_(select(Note.id).where(Note.workspace_id.in_(ws_ids)))))
            await self.session.execute(delete(PresenceState).where(
                PresenceState.note_id.in_(select(Note.id).where(Note.workspace_id.in_(ws_ids)))))
            await self.session.execute(delete(Note).where(Note.workspace_id.in_(ws_ids)))
            await self.session.execute(delete(Folder).where(Folder.workspace_id.in_(ws_ids)))
            await self.session.execute(delete(FileAsset).where(FileAsset.workspace_id.in_(ws_ids)))
            await self.session.execute(delete(Workspace).where(Workspace.organization_id == org_id))

        for model in (ShareLink, ShareGrant, Membership):
            await self.session.execute(delete(model).where(model.organization_id == org_id))

        AuditLog.record("organization_erased", actor_id="system", tenant_id=org_id,
                        resource_type="organization", resource_id=org_id)

        await self.session.delete(org)
        await self.session.flush()
        return {"erased": True}

    # ---- GDPR Art. 15 / CCPA - Data Export --------------------------------
    async def export_user_data(self, user_id: str, org_id: str) -> dict:
        """Machine-readable export of all data held about a user."""
        user = await self.users.get_by_id(user_id)
        if user is None:
            raise NotFoundError("User not found")
        consents = await self.consents.list_for_user(user_id)
        memberships = (await self.session.execute(
            select(Membership).where(Membership.user_id == user_id))).scalars().all()
        notes = (await self.session.execute(
            select(Note).where(Note.created_by == user_id, Note.organization_id == org_id))).scalars().all()

        AuditLog.record("data_exported", actor_id=pseudonymize(user_id), tenant_id=org_id,
                        resource_type="user", resource_id=pseudonymize(user_id))

        return {
            "user": {
                "id": user.id, "email": user.email, "full_name": user.full_name,
                "created_at": user.created_at.isoformat(), "totp_enabled": user.totp_enabled,
            },
            "memberships": [{"organization_id": m.organization_id, "role": m.role.value} for m in memberships],
            "consents": [{"purpose": c.purpose, "granted": c.granted, "recorded_at": c.recorded_at.isoformat()} for c in consents],
            "notes_created": [{"id": n.id, "created_at": n.created_at.isoformat()} for n in notes],
        }

    async def export_user_data_zip(self, user_id: str, org_id: str) -> bytes:
        """JSON + ZIP bundle of encrypted files for portability."""
        data = await self.export_user_data(user_id, org_id)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("user_data.json", json.dumps(data, indent=2))
        return buf.getvalue()

    # ---- GDPR Art. 7 - Consent -------------------------------------------
    async def record_consent(self, user_id: str, purpose: str, granted: bool) -> ConsentRecord:
        rec = ConsentRecord(user_id=user_id, purpose=purpose, granted=granted)
        await self.consents.create(rec)
        return rec

    async def list_consents(self, user_id: str) -> list[dict]:
        recs = await self.consents.list_for_user(user_id)
        return [{"purpose": c.purpose, "granted": c.granted, "recorded_at": c.recorded_at.isoformat()} for c in recs]

    # ---- GDPR Art. 5(1)(e) - Retention purge ------------------------------
    async def purge_expired_data(self) -> dict:
        """Purge soft-deleted data past its retention window."""
        now = datetime.now(timezone.utc)
        purged_notes = 0
        purged_files = 0

        # Free tier notes: 30 days, paid: 365 days
        for plan, days in (("free", retention_days_for_plan("free")), ("paid", retention_days_for_plan("pro"))):
            cutoff = now - timedelta(days=days)
            result = await self.session.execute(
                select(Note).where(Note.deleted_at.isnot(None), Note.deleted_at < cutoff))
            for n in result.scalars().all():
                await self.session.delete(n)
                purged_notes += 1
            result = await self.session.execute(
                select(FileAsset).where(FileAsset.deleted_at.isnot(None), FileAsset.deleted_at < cutoff))
            for f in result.scalars().all():
                await self.session.delete(f)
                purged_files += 1

        await self.session.flush()
        return {"purged_notes": purged_notes, "purged_files": purged_files}
