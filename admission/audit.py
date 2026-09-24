"""Read-side API over the append-only audit log.

The log itself is written by ``Store`` (one place, fsync + seq). This service
only filters it. All lookups read the durable log (not the derived snapshot),
so audit answers stay correct even immediately after crash recovery.
"""
from __future__ import annotations

from admission.clock import parse_ts
from admission.storage import Store


class AuditService:
    def __init__(self, store: Store) -> None:
        self.store = store

    def all_events(self) -> list[dict]:
        return self.store.read_audit()

    def by_request_id(self, request_id: str) -> list[dict]:
        return [e for e in self.all_events() if e.get("request_id") == request_id]

    def by_type(self, event_type: str) -> list[dict]:
        return [e for e in self.all_events() if e.get("event_type") == event_type]

    def between(self, start_iso: str | None = None, end_iso: str | None = None) -> list[dict]:
        start = parse_ts(start_iso) if start_iso else None
        end = parse_ts(end_iso) if end_iso else None
        out = []
        for event in self.all_events():
            ts = parse_ts(event["occurred_at"])
            if start is not None and ts < start:
                continue
            if end is not None and ts > end:
                continue
            out.append(event)
        return out

    def last_seq(self) -> int:
        events = self.all_events()
        return events[-1]["seq"] if events else 0
