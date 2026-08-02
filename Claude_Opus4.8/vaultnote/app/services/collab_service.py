"""Real-time collaboration simulation: presence + simplified OT.

Presence and the recent-operation log are in-process (a single-node demo). The
public surface is CRDT/OT-ready: operations are expressed against a base version
and transformed against concurrent operations before being applied, which is the
contract a Redis/websocket fan-out layer would plug into unchanged.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from app.schemas import NoteOperation


@dataclass
class _Op:
    version: int
    kind: str      # insert|delete
    position: int
    text: str
    length: int


def _transform_position(pos: int, other: _Op) -> int:
    """Transform an index against a concurrent op that already applied."""
    if other.kind == "insert":
        if other.position <= pos:
            return pos + len(other.text)
        return pos
    # delete
    if other.position < pos:
        return max(other.position, pos - other.length)
    return pos


class CollaborationEngine:
    """Process-wide singleton holding presence and op logs per note."""

    PRESENCE_TTL = 30.0

    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._presence: dict[str, dict[str, float]] = {}
        self._oplog: dict[str, list[_Op]] = {}

    # --- Presence ----------------------------------------------------------
    def heartbeat(self, note_id: str, user_id: str) -> None:
        with self._lock:
            self._presence.setdefault(note_id, {})[user_id] = self._clock()

    def active_users(self, note_id: str) -> list[str]:
        cutoff = self._clock() - self.PRESENCE_TTL
        with self._lock:
            users = self._presence.get(note_id, {})
            live = [u for u, ts in users.items() if ts >= cutoff]
            # prune expired entries
            self._presence[note_id] = {u: users[u] for u in live}
            return sorted(live)

    def leave(self, note_id: str, user_id: str) -> None:
        with self._lock:
            self._presence.get(note_id, {}).pop(user_id, None)

    # --- Simplified operational transform ---------------------------------
    def transform(self, note_id: str, current_version: int,
                  op: NoteOperation) -> _Op:
        """Rebase ``op`` (issued against ``op.base_version``) onto current state."""
        with self._lock:
            concurrent = [
                logged for logged in self._oplog.get(note_id, [])
                if logged.version > op.base_version
            ]
        pos = op.position
        for other in concurrent:
            pos = _transform_position(pos, other)
        return _Op(
            version=current_version + 1, kind=op.op, position=pos,
            text=op.text, length=op.length,
        )

    @staticmethod
    def apply(body: str, op: _Op) -> str:
        pos = max(0, min(op.position, len(body)))
        if op.kind == "insert":
            return body[:pos] + op.text + body[pos:]
        end = max(pos, min(pos + op.length, len(body)))
        return body[:pos] + body[end:]

    def record(self, note_id: str, op: _Op) -> None:
        with self._lock:
            log = self._oplog.setdefault(note_id, [])
            log.append(op)
            # Bound memory: keep only the last 200 ops per note.
            if len(log) > 200:
                del log[:-200]

    def reset(self) -> None:
        with self._lock:
            self._presence.clear()
            self._oplog.clear()
