"""Data-access layer.

Every read/write is parameterized (SQLAlchemy core/ORM) — no string SQL is ever
built from user input, so SQL injection is structurally impossible. Repositories
that touch tenant-scoped tables REQUIRE an ``org_id`` and filter on it, which is
the enforcement point for tenant isolation.
"""

from app.repositories.audit_repo import AuditRepository
from app.repositories.billing_repo import BillingRepository
from app.repositories.content_repo import (
    FileRepository,
    FolderRepository,
    NoteRepository,
)
from app.repositories.org_repo import MembershipRepository, OrganizationRepository
from app.repositories.sharing_repo import ShareLinkRepository, ShareRepository
from app.repositories.user_repo import (
    ConsentRepository,
    PasswordResetRepository,
    SessionRepository,
    UserRepository,
)

__all__ = [
    "AuditRepository",
    "BillingRepository",
    "ConsentRepository",
    "FileRepository",
    "FolderRepository",
    "MembershipRepository",
    "NoteRepository",
    "OrganizationRepository",
    "PasswordResetRepository",
    "SessionRepository",
    "ShareLinkRepository",
    "ShareRepository",
    "UserRepository",
]
