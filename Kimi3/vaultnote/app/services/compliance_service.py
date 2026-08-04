"""
Compliance service: GDPR Art. 17 erasure, Art. 15/CCPA export, consent,
retention purge jobs.

Erasure removes both database rows AND the physical encrypted blobs on
disk. Retention enforcement applies each tenant's own plan window and is
scoped per-tenant (a tenant admin can only purge their own data; the
cross-tenant sweep is reserved for the automatic scheduled system job).
"""
from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance import AuditLog, retention_days_for_plan
from app.core.privacy import pseudonymize
from app.models.entities import (
    ConsentRecord,
    DownloadToken,
    FileAsset,
    Folder,
    Membership,
    Note,
    NoteOperation,
    Organization,
    PresenceState,
    RefreshToken,
    ShareGrant,
    ShareLink,
    Subscription,
    Workspace,
)
from app.repositories.repositories import (
    ConsentRepository,
    OrganizationRepository,
    UserRepository,
)
from app.services.file_service import delete_blob
from app.utils.exceptions import NotFoundError


class ComplianceService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.users = UserRepository(session)
        self.orgs = OrganizationRepository(session)
        self.consents = ConsentRepository(session)

    # ---- Helpers --------------------------------------------------------
    async def _file_paths(self, where) -> list[str]:
        result = await self.session.execute(select(FileAsset.storage_path).where(where))
        return [r[0] for r in result.all()]

    @staticmethod
    async def _delete_blobs(paths: list[str]) -> int:
        removed = 0
        for p in paths:
            await delete_blob(p)
            removed += 1
        return removed

    # ---- GDPR Art. 17 - Right to Erasure (user) --------------------------
    async def erase_user(self, user_id: str, org_id: str) -> dict:
        """Cascading deletion of all personal data for a user.

        GDPR Art. 17 - erasure; CCPA - right to delete. Includes the
        physical encrypted blobs of files the user uploaded.
        """
        user = await self.users.get_by_id(user_id)
        if user is None:
            raise NotFoundError("User not found")

        # Remove the user's file blobs from disk before deleting their rows.
        blob_paths = await self._file_paths(FileAsset.uploaded_by == user_id)
        await self._delete_blobs(blob_paths)

        await self.session.execute(delete(DownloadToken).where(
            DownloadToken.file_id.in_(select(FileAsset.id).where(FileAsset.uploaded_by == user_id))))
        await self.session.execute(delete(FileAsset).where(FileAsset.uploaded_by == user_id))
        await self.session.execute(delete(RefreshToken).where(RefreshToken.user_id == user_id))
        await self.session.execute(delete(ConsentRecord).where(ConsentRecord.user_id == user_id))
        await self.session.execute(delete(ShareGrant).where(ShareGrant.grantee_user_id == user_id))
        await self.session.execute(delete(Membership).where(Membership.user_id == user_id))

        await AuditLog.record(self.session, "user_erased", actor_id=pseudonymize(user_id),
                              tenant_id=org_id, resource_type="user",
                              resource_id=pseudonymize(user_id),
                              metadata={"blobs_removed": len(blob_paths)})

        await self.session.delete(user)
        await self.session.flush()
        return {"erased": True}

    # ---- GDPR Art. 17 - Right to Erasure (organization) -------------------
    async def erase_organization(self, org_id: str) -> dict:
        """Cascading deletion of an entire tenant and all its data,
        including every encrypted file blob stored on disk."""
        org = await self.orgs.get_by_id(org_id)
        if org is None:
            raise NotFoundError("Organization not found")

        # Collect blob paths BEFORE deleting rows, then unlink the files.
        blob_paths = await self._file_paths(FileAsset.organization_id == org_id)

        # Delete in dependency order
        ws_ids = [r[0] for r in (await self.session.execute(
            select(Workspace.id).where(Workspace.organization_id == org_id))).all()]

        await self.session.execute(delete(DownloadToken).where(
            DownloadToken.file_id.in_(select(FileAsset.id).where(FileAsset.organization_id == org_id))))

        if ws_ids:
            await self.session.execute(delete(NoteOperation).where(
                NoteOperation.note_id.in_(select(Note.id).where(Note.workspace_id.in_(ws_ids)))))
            await self.session.execute(delete(PresenceState).where(
                PresenceState.note_id.in_(select(Note.id).where(Note.workspace_id.in_(ws_ids)))))
            await self.session.execute(delete(Note).where(Note.workspace_id.in_(ws_ids)))
            await self.session.execute(delete(Folder).where(Folder.workspace_id.in_(ws_ids)))
            await self.session.execute(delete(FileAsset).where(FileAsset.workspace_id.in_(ws_ids)))
            await self.session.execute(delete(Workspace).where(Workspace.organization_id == org_id))

        await self.session.execute(delete(FileAsset).where(FileAsset.organization_id == org_id))
        for model in (ShareLink, ShareGrant, Membership, Subscription):
            await self.session.execute(delete(model).where(model.organization_id == org_id))

        await self.session.delete(org)
        await self.session.flush()

        # Physical blobs are unlinked only after the DB transaction succeeded.
        await self._delete_blobs(blob_paths)

        await AuditLog.record(self.session, "organization_erased", actor_id="system",
                              tenant_id=org_id, resource_type="organization",
                              resource_id=org_id, metadata={"blobs_removed": len(blob_paths)})
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
        files = (await self.session.execute(
            select(FileAsset).where(FileAsset.uploaded_by == user_id,
                                    FileAsset.organization_id == org_id))).scalars().all()

        await AuditLog.record(self.session, "data_exported", actor_id=pseudonymize(user_id),
                              tenant_id=org_id, resource_type="user", resource_id=pseudonymize(user_id))

        return {
            "user": {
                "id": user.id, "email": user.email, "full_name": user.full_name,
                "created_at": user.created_at.isoformat(), "totp_enabled": user.totp_enabled,
            },
            "memberships": [{"organization_id": m.organization_id, "role": m.role.value} for m in memberships],
            "consents": [{"purpose": c.purpose, "granted": c.granted, "recorded_at": c.recorded_at.isoformat()} for c in consents],
            "notes_created": [{"id": n.id, "created_at": n.created_at.isoformat()} for n in notes],
            "files_uploaded": [{"id": f.id, "size_bytes": f.size_bytes, "mime_type": f.mime_type,
                                "created_at": f.created_at.isoformat()} for f in files],
        }

    async def export_user_data_zip(self, user_id: str, org_id: str) -> bytes:
        """JSON + ZIP bundle: metadata document plus the user's encrypted
        file blobs, as promised by the export contract."""
        data = await self.export_user_data(user_id, org_id)
        files = (await self.session.execute(
            select(FileAsset).where(FileAsset.uploaded_by == user_id,
                                    FileAsset.organization_id == org_id))).scalars().all()

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("user_data.json", json.dumps(data, indent=2))
            for f in files:
                path = Path(f.storage_path)
                if path.is_file():
                    # Blobs stay encrypted in the export; they can only be
                    # opened with the tenant key (zero-knowledge preserved).
                    zf.write(path, arcname=f"files/{f.id}.enc")
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
    async def _plan_for_org(self, org_id: str) -> str:
        sub = (await self.session.execute(
            select(Subscription).where(Subscription.organization_id == org_id))).scalar_one_or_none()
        if sub is not None and sub.active:
            return sub.plan.value
        org = await self.orgs.get_by_id(org_id)
        return org.plan.value if org is not None else "free"

    async def purge_expired_data(self, org_id: str) -> dict:
        """Purge soft-deleted data past ITS OWN tenant's retention window.

        The plan filter is applied per tenant: a paid tenant's data is never
        purged using the shorter free-tier window, and one tenant's purge
        never touches another tenant's data. Expired file blobs are removed
        from disk as well.
        """
        plan = await self._plan_for_org(org_id)
        cutoff = datetime.now(UTC) - timedelta(days=retention_days_for_plan(plan))
        purged_notes = 0
        purged_files = 0

        result = await self.session.execute(
            select(Note).where(Note.organization_id == org_id,
                               Note.deleted_at.isnot(None), Note.deleted_at < cutoff))
        for n in result.scalars().all():
            await self.session.delete(n)
            purged_notes += 1

        result = await self.session.execute(
            select(FileAsset).where(FileAsset.organization_id == org_id,
                                    FileAsset.deleted_at.isnot(None), FileAsset.deleted_at < cutoff))
        blob_paths: list[str] = []
        for f in result.scalars().all():
            blob_paths.append(f.storage_path)
            await self.session.delete(f)
            purged_files += 1

        await self.session.flush()
        await self._delete_blobs(blob_paths)
        return {"purged_notes": purged_notes, "purged_files": purged_files, "plan": plan}

    async def purge_all_tenants(self) -> dict:
        """System maintenance sweep used by the automatic scheduled job.

        Applies each organization's own plan window - the free-tier cutoff
        is never applied to paid tenants.
        """
        result = await self.session.execute(
            select(Organization.id).where(Organization.deleted_at.is_(None)))
        totals = {"purged_notes": 0, "purged_files": 0, "tenants": 0}
        for (org_id,) in result.all():
            r = await self.purge_expired_data(org_id)
            totals["purged_notes"] += r["purged_notes"]
            totals["purged_files"] += r["purged_files"]
            totals["tenants"] += 1
        return totals
