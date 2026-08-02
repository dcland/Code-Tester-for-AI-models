"""Privacy-preserving analytics with differential privacy.

Aggregate counts returned to dashboards are perturbed with the Laplace mechanism
(configurable ε). Individual user activity cannot be reconstructed, and the
service exposes no per-user breakdowns — only noised org-level aggregates.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.exceptions import AuthorizationError
from app.core.privacy import DifferentialPrivacy
from app.models.organization import Role
from app.repositories import (
    FileRepository,
    MembershipRepository,
    NoteRepository,
)


@dataclass
class PrivateAnalytics:
    epsilon: float
    note_count: int
    file_count: int
    active_members: int
    storage_bytes: int
    note: str


class AnalyticsService:
    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._settings = settings
        self._notes = NoteRepository(session)
        self._files = FileRepository(session)
        self._members = MembershipRepository(session)

    async def org_dashboard(self, org_id: str, user_id: str,
                            epsilon: float | None = None) -> PrivateAnalytics:
        role = await self._members.get_role(org_id, user_id)
        if role is None or not role.at_least(Role.ADMIN):
            raise AuthorizationError("analytics require admin role")

        eps = epsilon or self._settings.default_dp_epsilon
        dp = DifferentialPrivacy(eps)

        true_notes = await self._notes.count(org_id)
        true_files = await self._files.count(org_id)
        true_members = await self._members.count_for_org(org_id)
        true_storage = await self._files.total_storage(org_id)

        # Apply calibrated Laplace noise to every released aggregate.
        return PrivateAnalytics(
            epsilon=eps,
            note_count=dp.privatize_count(true_notes),
            file_count=dp.privatize_count(true_files),
            active_members=dp.privatize_count(true_members),
            # Storage sensitivity is coarse-grained to buckets of 1 MiB.
            storage_bytes=int(dp.privatize_sum(true_storage, sensitivity=1024 * 1024)),
            note=(
                f"Values are differentially private (ε={eps}); "
                "small counts are noised and may not be exact."
            ),
        )
