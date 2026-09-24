"""In-process local storage.

A single :class:`threading.RLock` guards every collection so that compound
operations (e.g. "register signature + append audit event") are atomic with
respect to concurrent requests. There is deliberately one lock per store
instance: the data volume is tiny and correctness/explainability beats
contention micro-optimisation here.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from gate.models import AuditEvent, PolicyVersion, SignatureRecord, StoredKey


@dataclass
class LocalStore:
    keys: dict[str, StoredKey] = field(default_factory=dict)
    key_order: list[str] = field(default_factory=list)
    active_key_id: str | None = None
    signatures: dict[str, SignatureRecord] = field(default_factory=dict)
    policies: dict[int, PolicyVersion] = field(default_factory=dict)
    policy_order: list[int] = field(default_factory=list)
    audit: list[AuditEvent] = field(default_factory=list)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def snapshot_audit(self) -> list[AuditEvent]:
        with self._lock:
            return list(self.audit)
