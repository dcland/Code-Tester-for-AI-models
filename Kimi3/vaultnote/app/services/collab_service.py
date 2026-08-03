"""
Real-time collaboration simulation: presence + CRDT-ready operation log.

Uses a Lamport logical clock for total ordering of operations.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import WrappedKey, encryption_service
from app.models.entities import NoteOperation, PresenceState
from app.repositories.repositories import (
    NoteOperationRepository, NoteRepository, OrganizationRepository, PresenceRepository,
)
from app.utils.exceptions import NotFoundError


class CollabService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.ops = NoteOperationRepository(session)
        self.presence = PresenceRepository(session)
        self.notes = NoteRepository(session)
        self.orgs = OrganizationRepository(session)

    async def _tenant_kek(self, org_id: str) -> bytes:
        org = await self.orgs.get_by_id(org_id)
        if org is None:
            raise NotFoundError("Organization not found")
        return encryption_service.decrypt_kek(WrappedKey(org.kek_ciphertext, org.kek_nonce))

    async def submit_operation(
        self, org_id: str, note_id: str, user_id: str,
        op_type: str, position: int, content: str,
    ) -> dict:
        note = await self.notes.get_by_id_and_org(note_id, org_id)
        if note is None:
            raise NotFoundError("Note not found")
        kek = await self._tenant_kek(org_id)
        dek = encryption_service.unwrap_dek(WrappedKey(note.dek_ciphertext, note.dek_nonce), kek)
        ct, nonce = encryption_service.encrypt(content.encode(), dek)

        lamport = await self.ops.max_lamport(note_id) + 1
        op = NoteOperation(
            note_id=note_id, user_id=user_id, lamport=lamport,
            op_type=op_type, position=position,
            content_encrypted=ct, content_nonce=nonce,
        )
        await self.ops.create(op)
        return {"lamport": lamport}

    async def get_operations(self, org_id: str, note_id: str) -> list[dict]:
        note = await self.notes.get_by_id_and_org(note_id, org_id)
        if note is None:
            raise NotFoundError("Note not found")
        kek = await self._tenant_kek(org_id)
        dek = encryption_service.unwrap_dek(WrappedKey(note.dek_ciphertext, note.dek_nonce), kek)
        out: list[dict] = []
        for op in await self.ops.list_operations(note_id):
            content = encryption_service.decrypt(op.content_encrypted, op.content_nonce, dek).decode()
            out.append({
                "lamport": op.lamport, "op_type": op.op_type,
                "position": op.position, "content": content, "user_id": op.user_id,
            })
        return out

    async def update_presence(self, note_id: str, user_id: str, cursor_position: int) -> None:
        from sqlalchemy import select
        result = await self.session.execute(
            select(PresenceState).where(PresenceState.note_id == note_id, PresenceState.user_id == user_id)
        )
        state = result.scalar_one_or_none()
        if state is None:
            state = PresenceState(note_id=note_id, user_id=user_id, cursor_position=cursor_position)
            self.session.add(state)
        else:
            state.cursor_position = cursor_position
            state.last_seen = datetime.now(timezone.utc)
        await self.session.flush()

    async def get_presence(self, note_id: str) -> list[dict]:
        states = await self.presence.list_for_note(note_id)
        return [{"user_id": s.user_id, "cursor_position": s.cursor_position, "last_seen": s.last_seen.isoformat()} for s in states]
