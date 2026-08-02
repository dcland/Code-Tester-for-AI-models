"""Compliance toolkit: erasure, portability export, consent, retention purge."""

from __future__ import annotations

import io
import json
import zipfile
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance import AuditAction, ConsentType
from app.core.config import Settings
from app.core.encryption import EnvelopeEncryptor
from app.core.exceptions import AuthorizationError, NotFoundError
from app.db.base import utcnow
from app.models.billing import Invoice, Subscription, UsageRecord
from app.models.content import File, Folder, Note
from app.models.organization import Membership, Organization, Role
from app.models.sharing import Share, ShareLink
from app.models.user import Consent, PasswordReset, Session, User
from app.repositories import (
    ConsentRepository,
    MembershipRepository,
    OrganizationRepository,
)
from app.services.audit_service import AuditService
from app.services.note_service import _note_aad
from app.services.file_service import _file_aad
from app.utils.files import BlobStore


class ComplianceService:
    def __init__(self, session: AsyncSession, settings: Settings,
                 encryptor: EnvelopeEncryptor, blob_store: BlobStore) -> None:
        self._s = session
        self._settings = settings
        self._enc = encryptor
        self._blobs = blob_store
        self._orgs = OrganizationRepository(session)
        self._members = MembershipRepository(session)
        self._consents = ConsentRepository(session)
        self._audit = AuditService(session, settings)

    # --- Consent management (GDPR Art. 7) ---------------------------------
    async def set_consent(self, user_id: str, consent_type: str,
                          granted: bool) -> None:
        await self._consents.set(user_id, consent_type, granted)
        await self._audit.record(
            action=(AuditAction.CONSENT_GRANTED if granted
                    else AuditAction.CONSENT_WITHDRAWN),
            org_id=None, actor_user_id=user_id, context={"type": consent_type},
        )
        await self._s.commit()

    async def get_consents(self, user_id: str) -> dict[str, tuple[bool, object]]:
        latest = await self._consents.latest(user_id)
        # Default everything to not-granted so the response is exhaustive.
        result: dict[str, tuple[bool, object]] = {}
        for ct in ConsentType:
            result[ct.value] = latest.get(ct.value, (False, None))
        return result

    # --- Data export (GDPR Art. 15 / CCPA right to know) ------------------
    async def export_user_data(self, user_id: str) -> bytes:
        """Return a ZIP: machine-readable JSON of the subject's data + file blobs.

        The subject is entitled to their own plaintext, so note bodies are
        decrypted into the JSON. Raw encrypted file blobs are also included.
        """
        user = await self._s.get(User, user_id)
        if user is None or user.deleted_at is not None:
            raise NotFoundError("user not found")

        manifest: dict = {
            "schema": "vaultnote.export/v1",
            "generated_at": utcnow().isoformat(),
            "account": {
                "id": user.id,
                "email": user.email,
                "display_name": user.display_name,
                "created_at": user.created_at.isoformat(),
            },
            "consents": [],
            "organizations": [],
        }
        for ct, (granted, ts) in (await self.get_consents(user_id)).items():
            manifest["consents"].append({
                "type": ct, "granted": granted,
                "updated_at": ts.isoformat() if ts else None,
            })

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for membership in await self._members.list_for_user(user_id):
                org = await self._orgs.get(membership.org_id)
                if org is None:
                    continue
                org_block: dict = {
                    "id": org.id, "name": org.name, "role": membership.role,
                    "notes": [], "files": [],
                }
                tmk = org.wrapped_master_key

                notes = (await self._s.execute(
                    select(Note).where(
                        Note.org_id == org.id, Note.owner_id == user_id,
                        Note.deleted_at.is_(None),
                    )
                )).scalars()
                for n in notes:
                    title_b, body_b = self._enc.decrypt_many(
                        tmk, n.wrapped_dek,
                        [n.title_ciphertext, n.body_ciphertext],
                        _note_aad(org.id, n.id),
                    )
                    org_block["notes"].append({
                        "id": n.id, "title": title_b.decode(),
                        "body": body_b.decode(),
                        "created_at": n.created_at.isoformat(),
                    })

                files = (await self._s.execute(
                    select(File).where(
                        File.org_id == org.id, File.owner_id == user_id,
                        File.deleted_at.is_(None),
                    )
                )).scalars()
                for f in files:
                    (name_b,) = self._enc.decrypt_many(
                        tmk, f.wrapped_dek, [f.filename_ciphertext],
                        _file_aad(org.id, f.id),
                    )
                    org_block["files"].append({
                        "id": f.id, "filename": name_b.decode(),
                        "content_type": f.content_type, "size_bytes": f.size_bytes,
                        "sha256": f.content_sha256,
                        "blob": f"files/{org.id}/{f.id}.enc",
                    })
                    try:
                        blob = self._blobs.read(f.storage_key)
                        zf.writestr(f"files/{org.id}/{f.id}.enc", blob)
                    except Exception:
                        pass  # blob missing; metadata still exported
                manifest["organizations"].append(org_block)

            zf.writestr("data.json", json.dumps(manifest, indent=2))

        await self._audit.record(
            action=AuditAction.DATA_EXPORTED, org_id=None, actor_user_id=user_id
        )
        await self._s.commit()
        return buffer.getvalue()

    # --- Right to erasure (GDPR Art. 17) ----------------------------------
    async def _collect_file_keys_for_user(self, user_id: str) -> list[str]:
        rows = (await self._s.execute(
            select(File.storage_key).where(File.owner_id == user_id)
        )).scalars()
        return list(rows)

    async def _collect_file_keys_for_org(self, org_id: str) -> list[str]:
        rows = (await self._s.execute(
            select(File.storage_key).where(File.org_id == org_id)
        )).scalars()
        return list(rows)

    async def erase_user(self, user_id: str) -> None:
        """Cascading deletion of a user and everything they own.

        Order: purge on-disk encrypted blobs, delete the user (DB cascades wipe
        memberships/sessions/notes/files/consents/shares), then erase any org
        left with no members. Audit logs are pseudonymized and PII-free, so they
        are retained for compliance (Art. 17(3)(b)).
        """
        user = await self._s.get(User, user_id)
        if user is None:
            raise NotFoundError("user not found")

        # Orgs the user belongs to (to check for orphaning afterwards).
        org_ids = [m.org_id for m in await self._members.list_for_user(user_id)]

        # Delete blobs owned by the user from disk before the rows vanish.
        for key in await self._collect_file_keys_for_user(user_id):
            self._blobs.delete(key)

        await self._s.execute(delete(User).where(User.id == user_id))
        await self._s.flush()

        # Erase orgs that now have zero members (sole-owner cleanup).
        for org_id in org_ids:
            remaining = (await self._s.execute(
                select(func.count()).select_from(Membership).where(
                    Membership.org_id == org_id
                )
            )).scalar_one()
            if remaining == 0:
                await self._erase_org_rows(org_id)

        await self._audit.record(
            action=AuditAction.USER_ERASED, org_id=None, actor_user_id=None,
            resource_type="user", resource_id=user_id,
        )
        await self._s.commit()

    async def _erase_org_rows(self, org_id: str) -> None:
        for key in await self._collect_file_keys_for_org(org_id):
            self._blobs.delete(key)
        # Explicit deletes (defensive; FK cascade also covers most of these).
        await self._s.execute(delete(Share).where(Share.org_id == org_id))
        await self._s.execute(delete(ShareLink).where(ShareLink.org_id == org_id))
        await self._s.execute(delete(Note).where(Note.org_id == org_id))
        await self._s.execute(delete(File).where(File.org_id == org_id))
        await self._s.execute(delete(Folder).where(Folder.org_id == org_id))
        await self._s.execute(delete(Invoice).where(Invoice.org_id == org_id))
        await self._s.execute(delete(Subscription).where(Subscription.org_id == org_id))
        await self._s.execute(delete(UsageRecord).where(UsageRecord.org_id == org_id))
        await self._s.execute(delete(Membership).where(Membership.org_id == org_id))
        await self._s.execute(delete(Organization).where(Organization.id == org_id))

    async def erase_organization(self, org_id: str, actor_id: str) -> None:
        role = await self._members.get_role(org_id, actor_id)
        if role is None or role is not Role.OWNER:
            raise AuthorizationError("only the organization owner may erase it")
        await self._erase_org_rows(org_id)
        await self._audit.record(
            action=AuditAction.ORG_ERASED, org_id=org_id, actor_user_id=actor_id,
            resource_type="organization", resource_id=org_id,
        )
        await self._s.commit()

    # --- Retention purge (GDPR Art. 5(1)(e)) ------------------------------
    async def purge_expired(self) -> dict[str, int]:
        """Hard-delete soft-deleted content past its tenant's retention window."""
        purged_notes = 0
        purged_files = 0
        orgs = (await self._s.execute(select(Organization))).scalars().all()
        for org in orgs:
            cutoff = utcnow() - timedelta(days=org.retention_days)

            stale_files = (await self._s.execute(
                select(File).where(
                    File.org_id == org.id, File.deleted_at.is_not(None),
                    File.deleted_at < cutoff,
                )
            )).scalars().all()
            for f in stale_files:
                self._blobs.delete(f.storage_key)
                await self._s.execute(delete(File).where(File.id == f.id))
                purged_files += 1

            result = await self._s.execute(
                delete(Note).where(
                    Note.org_id == org.id, Note.deleted_at.is_not(None),
                    Note.deleted_at < cutoff,
                )
            )
            purged_notes += result.rowcount or 0

            if purged_notes or purged_files:
                await self._audit.record(
                    action=AuditAction.RETENTION_PURGE, org_id=org.id,
                    actor_user_id=None,
                    context={"notes": purged_notes, "files": purged_files},
                )
        await self._s.commit()
        return {"notes": purged_notes, "files": purged_files}
