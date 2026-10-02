"""File-backed local state: single-writer lock, atomic writes, crash recovery.

Durability model
----------------
* ``audit.log`` (JSON Lines) is the append-only source of truth. Every commit
  appends one or more events with strictly increasing sequence numbers and
  fsyncs the file before the lock is released.
* ``state.json`` is a derived snapshot of the audit log, replaced atomically
  (write temp + fsync + os.replace) on every commit.
* On open, if the snapshot is missing, older than the log, or unreadable, the
  snapshot is rebuilt by replaying audit events (see ``admission.replay``).
* An fcntl flock on ``lock.file`` serializes writers across processes; an
  in-process threading lock serializes threads within one process.

A transaction therefore gives: no duplicate records (writer serialisation +
event dedup by request_id enforced by services), no torn state (atomic replace
+ fsync), and recovery from mid-commit crashes (log replay).
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import threading
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from admission.replay import STATE_FORMAT, apply_events, rebuild_state

STATE_FILE = "state.json"
AUDIT_FILE = "audit.log"
LOCK_FILE = "lock.file"

# Serialises all Store instances inside one process. Each transaction also
# takes an flock (serialises across processes and between threads via separate
# fds), but this module-level lock also protects shared-name temp files when
# several Store objects in this process commit concurrently.
_GLOBAL_LOCK = threading.RLock()


class Store:
    def __init__(self, data_dir: str = ".admission-data") -> None:
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._state_path = self.dir / STATE_FILE
        self._audit_path = self.dir / AUDIT_FILE
        self._lock_path = self.dir / LOCK_FILE
        self._thread_lock = threading.RLock()
        self._lock_fd: int | None = None
        self.state: dict[str, Any] = self._load()

    # ------------------------------------------------------------------ open
    def _load(self) -> dict[str, Any]:
        events = self._read_log()
        log_seq = events[-1]["seq"] if events else 0
        snapshot: dict[str, Any] | None = None
        try:
            if self._state_path.exists():
                snapshot = json.loads(self._state_path.read_text("utf-8"))
        except (json.JSONDecodeError, OSError):
            snapshot = None
        if (snapshot is None
                or snapshot.get("format") != STATE_FORMAT
                or int(snapshot.get("last_seq", 0)) < log_seq):
            state = rebuild_state(events)
            self._write_state_atomic(state)
            return state
        return snapshot

    def _read_log(self) -> list[dict[str, Any]]:
        if not self._audit_path.exists():
            return []
        events: list[dict[str, Any]] = []
        text = self._audit_path.read_text("utf-8")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                # A torn final line (crash mid-append): stop replay here. Any
                # later complete lines cannot exist (single writer, ordered).
                break
        return events

    # ------------------------------------------------------------------ write
    def _write_state_atomic(self, state: dict[str, Any]) -> None:
        # Unique temp name: concurrent Store instances (separate workers that
        # happen to share this process) must not replace each other's temp.
        tmp = self._state_path.with_name(
            f".state.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex[:8]}.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(state, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._state_path)
            # Durably record the directory entry change.
            dir_fd = os.open(self.dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if tmp.exists():
                tmp.unlink()

    def _append_log(self, events: list[dict[str, Any]]) -> None:
        with open(self._audit_path, "a", encoding="utf-8") as fh:
            fh.writelines(
                json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
                for event in events
            )
            fh.flush()
            os.fsync(fh.fileno())

    # ------------------------------------------------------------------ locks
    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        # Global in-process lock first (all Store instances), then the
        # cross-process file lock.
        _GLOBAL_LOCK.acquire()
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            _GLOBAL_LOCK.release()

    # ------------------------------------------------------------------ API
    @contextlib.contextmanager
    def transaction(self) -> Iterator[dict[str, Any]]:
        """Serialised read-modify-write.

        The yielded state dict is the live snapshot. Mutate it and return; on
        clean exit the snapshot is atomically persisted. Events added via
        ``state.setdefault('_pending_events', [])`` are appended durably first.
        """
        with self._locked():
            # Re-read snapshot in case another process advanced the log while
            # this process held no lock (its in-memory copy went stale).
            on_disk = self._read_log()
            log_seq = on_disk[-1]["seq"] if on_disk else 0
            if log_seq > int(self.state.get("last_seq", 0)):
                self.state = rebuild_state(on_disk)
            # Snapshot in-memory state so a raised body rolls back fully:
            # neither staged events nor seq increments survive the exception.
            rollback_copy = json.loads(json.dumps(self.state))
            pending: list[dict[str, Any]] = []
            self.state["_pending_events"] = pending
            try:
                yield self.state
            except BaseException:
                # Restore the snapshot (the pending-events key was added after
                # the copy and is therefore dropped as well).
                self.state = rollback_copy
                raise
            if pending:
                # Durable log first; then derive the snapshot from the very
                # same events so state == projection(log prefix).
                self._append_log(pending)
                self.state.pop("_pending_events", None)
                apply_events(self.state, pending)
            else:
                self.state.pop("_pending_events", None)
            self._write_state_atomic(self.state)

    def emit(self, state: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        """Allocate the next seq and stage an event inside a transaction."""
        state["last_seq"] = int(state["last_seq"]) + 1
        event = dict(event)
        event["seq"] = state["last_seq"]
        state["_pending_events"].append(event)
        return event

    def snapshot(self) -> dict[str, Any]:
        """Read-only consistent copy (takes the lock to avoid torn reads)."""
        with self._locked():
            return json.loads(json.dumps({k: v for k, v in self.state.items()
                                          if k != "_pending_events"}))

    def append_audit(self, event: dict[str, Any]) -> dict[str, Any]:
        with self.transaction() as state:
            return self.emit(state, event)

    def read_audit(self) -> list[dict[str, Any]]:
        return self._read_log()
