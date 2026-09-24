"""Append-only audit trail.

Every state-changing or decision-making action is appended to one ordered
list while holding the same store lock that guards the state mutation, so a
multi-step action (e.g. policy publish + audit append) cannot leave the
journal ahead of or behind the state it describes.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable

from gate.models import AuditEvent
from gate.storage import LocalStore


class AuditLog:
    def __init__(
        self,
        store: LocalStore,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._store = store
        if clock is not None:
            self._clock = clock
        else:
            import time

            self._clock = time.time

    def append(self, event_type: str, payload: dict) -> AuditEvent:
        """Append an event. Callers must hold ``store.lock`` when this is
        part of a compound mutation; this method re-enters the same lock."""
        event = AuditEvent(
            event_id="evt-" + secrets.token_hex(8),
            timestamp=self._clock(),
            event_type=event_type,
            payload=dict(payload),
        )
        with self._store.lock:
            self._store.audit.append(event)
        return event

    def events(
        self,
        event_type: str | None = None,
        since: float | None = None,
        until: float | None = None,
    ) -> list[AuditEvent]:
        with self._store.lock:
            result: list[AuditEvent] = []
            for event in self._store.audit:
                if event_type is not None and event.event_type != event_type:
                    continue
                if since is not None and event.timestamp < since:
                    continue
                if until is not None and event.timestamp > until:
                    continue
                result.append(event)
            return result

    def by_key(self, key: str, value) -> list[AuditEvent]:
        """Return events whose JSON payload contains ``key == value``."""
        with self._store.lock:
            return [e for e in self._store.audit if e.payload.get(key) == value]
