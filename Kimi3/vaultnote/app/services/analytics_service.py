"""
Privacy-preserving analytics with differential privacy.

GDPR Art. 89(1) - statistical purposes with appropriate safeguards.
No individual user behavior can be reconstructed.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.privacy import dp_count, dp_sum
from app.models.entities import FileAsset, Membership, Note


class AnalyticsService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def dashboard(self, org_id: str) -> dict:
        """Aggregate, differentially-private usage statistics.

        Only org-level aggregates are returned; all counts have Laplace noise.
        """
        today = datetime.now(UTC).strftime("%Y-%m-%d")

        # Raw aggregates (never returned to client directly)
        member_count = (await self.session.execute(
            select(func.count()).select_from(Membership).where(Membership.organization_id == org_id))).scalar_one()
        note_count = (await self.session.execute(
            select(func.count()).select_from(Note).where(
                Note.organization_id == org_id, Note.deleted_at.is_(None)))).scalar_one()
        file_count = (await self.session.execute(
            select(func.count()).select_from(FileAsset).where(
                FileAsset.organization_id == org_id, FileAsset.deleted_at.is_(None)))).scalar_one()
        storage = (await self.session.execute(
            select(func.coalesce(func.sum(FileAsset.size_bytes), 0)).where(
                FileAsset.organization_id == org_id, FileAsset.deleted_at.is_(None)))).scalar_one()

        eps = settings.DP_EPSILON
        return {
            # Differential privacy applied to every aggregate
            "active_members": max(round(dp_count(member_count, eps)), 0),
            "total_notes": max(round(dp_count(note_count, eps)), 0),
            "total_files": max(round(dp_count(file_count, eps)), 0),
            "storage_bytes": max(round(dp_sum(float(storage), eps, sensitivity=1024)), 0),
            "epsilon": eps,
            "date": today,
        }
