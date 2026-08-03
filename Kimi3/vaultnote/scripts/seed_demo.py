"""
Seed the demo database with two organizations, users, notes, and files.

Run: python -m scripts.seed_demo
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Ensure project root on path when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.models.database import async_session_factory, init_db
from app.models.entities import Membership, Role, User, Workspace
from app.repositories.repositories import MembershipRepository, UserRepository, WorkspaceRepository
from app.services.auth_service import AuthService
from app.services.file_service import FileService
from app.services.note_service import NoteService

# Minimal valid PNG magic bytes + IHDR stub for demo file upload
_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc```\x00\x00\x00\x04\x00\x01"
    b"\xf6\x178U\x00\x00\x00\x00IEND\xaeB`\x82"
)


async def seed() -> None:
    await init_db()
    async with async_session_factory() as session:
        auth = AuthService(session)
        note_svc = NoteService(session)
        file_svc = FileService(session)
        ws_repo = WorkspaceRepository(session)
        membership_repo = MembershipRepository(session)
        user_repo = UserRepository(session)

        # --- Org 1: Acme Corp ---
        alice, acme = await auth.register(
            "alice@acme.example", "SecurePass1!x", "Alice Admin", "Acme Corp")
        acme_ws = Workspace(organization_id=acme.id, name="Engineering")
        await ws_repo.create(acme_ws)

        bob = User(email="bob@acme.example", hashed_password=auth.users.model.hashed_password.type.python_type if False else "", full_name="Bob Member")
        # Use auth service to hash bob's password properly
        from app.core.security import hash_password
        bob.hashed_password = hash_password("SecurePass1!x")
        await user_repo.create(bob)
        await membership_repo.create(Membership(user_id=bob.id, organization_id=acme.id, role=Role.MEMBER))

        note1 = await note_svc.create_note(acme.id, acme_ws.id, alice.id,
                                           "Acme Roadmap", "Q3 OKRs and milestones")
        await note_svc.create_folder(acme.id, acme_ws.id, "Product Specs", None)
        png = _PNG_BYTES
        await file_svc.upload_file(acme.id, acme_ws.id, alice.id, "logo.png", png)

        # --- Org 2: Globex ---
        carol, globex = await auth.register(
            "carol@globex.example", "SecurePass1!x", "Carol Owner", "Globex")
        globex_ws = Workspace(organization_id=globex.id, name="Research")
        await ws_repo.create(globex_ws)
        await note_svc.create_note(globex.id, globex_ws.id, carol.id,
                                   "Globex Vision", "Long-term research agenda")

        await session.commit()

        print("Seeded demo data:")
        print(f"  Acme Corp   (org={acme.id})  users: alice@acme.example, bob@acme.example")
        print(f"  Globex      (org={globex.id}) user:  carol@globex.example")
        print(f"  Acme workspace: {acme_ws.id}")
        print(f"  Password for all demo users: SecurePass1!x")


if __name__ == "__main__":
    asyncio.run(seed())
