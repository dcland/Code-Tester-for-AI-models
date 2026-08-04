"""
Seed the demo database with two organizations, users, notes, and files.

Run: python -m scripts.seed_demo

Privacy posture: the script never prints emails or passwords. Demo
credentials come from the DEMO_SEED_PASSWORD environment variable; if it is
unset, a random password is generated and written to a local-only,
git-ignored file (scripts/.demo_credentials, mode 0600) instead of stdout.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import sys
from pathlib import Path

# Ensure project root on path when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.security import hash_password
from app.models.database import async_session_factory, init_db
from app.models.entities import Membership, Role, User, Workspace
from app.repositories.repositories import (
    MembershipRepository,
    UserRepository,
    WorkspaceRepository,
)
from app.services.auth_service import AuthService
from app.services.file_service import FileService
from app.services.note_service import NoteService

# Minimal valid PNG magic bytes + IHDR stub for demo file upload
_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc```\x00\x00\x00\x04\x00\x01"
    b"\xf6\x178U\x00\x00\x00\x00IEND\xaeB`\x82"
)

_CREDENTIALS_PATH = Path(__file__).resolve().parent / ".demo_credentials"


def _demo_password() -> str:
    """Password from env, or a generated one stored in a 0600 local file."""
    from_env = os.environ.get("DEMO_SEED_PASSWORD")
    if from_env:
        return from_env
    generated = f"Demo-{secrets.token_urlsafe(16)}!"
    _CREDENTIALS_PATH.write_text(f"demo password: {generated}\n")
    _CREDENTIALS_PATH.chmod(0o600)
    return generated


async def seed() -> None:
    await init_db()
    password = _demo_password()
    async with async_session_factory() as session:
        auth = AuthService(session)
        note_svc = NoteService(session)
        file_svc = FileService(session)
        ws_repo = WorkspaceRepository(session)
        membership_repo = MembershipRepository(session)
        user_repo = UserRepository(session)

        # --- Org 1: Acme Corp ---
        alice, acme = await auth.register(
            "alice@acme.example", password, "Alice Admin", "Acme Corp")
        acme_ws = Workspace(organization_id=acme.id, name="Engineering")
        await ws_repo.create(acme_ws)

        bob = User(email="bob@acme.example", hashed_password=hash_password(password),
                   full_name="Bob Member")
        await user_repo.create(bob)
        await membership_repo.create(
            Membership(user_id=bob.id, organization_id=acme.id, role=Role.MEMBER))

        await note_svc.create_note(acme.id, acme_ws.id, alice.id,
                                   "Acme Roadmap", "Q3 OKRs and milestones")
        await note_svc.create_folder(acme.id, acme_ws.id, "Product Specs", None)
        await file_svc.upload_file(acme.id, acme_ws.id, alice.id, "logo.png", _PNG_BYTES)

        # --- Org 2: Globex ---
        carol, globex = await auth.register(
            "carol@globex.example", password, "Carol Owner", "Globex")
        globex_ws = Workspace(organization_id=globex.id, name="Research")
        await ws_repo.create(globex_ws)
        await note_svc.create_note(globex.id, globex_ws.id, carol.id,
                                   "Globex Vision", "Long-term research agenda")

        await session.commit()

        # No PII (emails) and no secrets (passwords) in output.
        print("Seeded demo data:")
        print(f"  Org 1 'Acme Corp' (id={acme.id}) - 2 users, 1 workspace, 1 note, 1 folder, 1 file")
        print(f"  Org 2 'Globex'    (id={globex.id}) - 1 user, 1 workspace, 1 note")
        if "DEMO_SEED_PASSWORD" not in os.environ:
            print(f"  Demo password written to {_CREDENTIALS_PATH} (mode 0600)")


if __name__ == "__main__":
    asyncio.run(seed())
