"""Key lifecycle: generation, rotation and revocation.

Only key-administrators (role ``key_admin``) may generate, rotate or revoke.
Rotation marks the old key ``rotated_at``/``rotated_to`` and creates a new
active key; it never deletes the old record, so signatures made with the old
key remain explainable and queryable — but they stop counting towards any
admission quorum immediately and retroactively (see ``signing._classify``).
Signers must re-sign with the new active key to make the artifact pass again.
"""
from __future__ import annotations

import uuid
from datetime import timedelta

from admission.clock import Clock, utcnow_str
from admission.crypto import generate_secret
from admission.models import (
    AdmissionError,
    Caller,
    ErrorCode,
    KeyExistsError,
    KeyNotFoundError,
    KeyRecord,
    KeyRevokedError,
    KeyRotatedError,
)
from admission.storage import Store

KEY_ADMIN_ROLE = "key_admin"
DEFAULT_KEY_TTL = timedelta(days=90)


class PermissionDeniedError(AdmissionError):
    error_code = ErrorCode.PERMISSION_DENIED
    http_status = 403


def _require_key_admin(caller: Caller, action: str) -> None:
    if not caller.has_role(KEY_ADMIN_ROLE):
        raise PermissionDeniedError(
            f"caller '{caller.id}' lacks role '{KEY_ADMIN_ROLE}' required to {action}",
            details={"caller": caller.summary(), "required_role": KEY_ADMIN_ROLE},
        )


class KeyService:
    def __init__(self, store: Store, clock: Clock) -> None:
        self.store = store
        self.clock = clock

    # -------------------------------------------------------------- helpers
    def get(self, key_id: str) -> KeyRecord:
        data = self.store.state["keys"].get(key_id)
        if data is None:
            raise KeyNotFoundError(
                f"key '{key_id}' does not exist",
                details={"key_id": key_id},
            )
        return KeyRecord(**data)

    def list_keys(self) -> list[dict]:
        return [KeyRecord(**k).summary() for k in self.store.state["keys"].values()]

    def grant_signer(self, caller: Caller, key_id: str, signer_id: str) -> dict:
        """Authorize ``signer_id`` to sign with ``key_id``."""
        _require_key_admin(caller, "manage key grants")
        now = utcnow_str(self.clock)
        with self.store.transaction() as state:
            if key_id not in state["keys"]:
                raise KeyNotFoundError(
                    f"cannot grant unknown key '{key_id}'",
                    details={"key_id": key_id},
                )
            grantees = state["key_grants"].setdefault(key_id, [])
            if signer_id not in grantees:
                self.store.emit(state, {
                    "event_type": "key_granted",
                    "occurred_at": now,
                    "actor": caller.id,
                    "request_id": f"grant-{key_id}-{signer_id}-{now}",
                    "payload": {"key_id": key_id, "caller_id": signer_id},
                })
            return {"key_id": key_id, "grantees": [*grantees,
                    *( [] if signer_id in grantees else [signer_id])]}

    def revoke_signer_grant(self, caller: Caller, key_id: str, signer_id: str) -> dict:
        _require_key_admin(caller, "manage key grants")
        now = utcnow_str(self.clock)
        with self.store.transaction() as state:
            if key_id not in state["keys"]:
                raise KeyNotFoundError(
                    f"cannot revoke grant on unknown key '{key_id}'",
                    details={"key_id": key_id},
                )
            grantees = state["key_grants"].get(key_id, [])
            if signer_id in grantees:
                self.store.emit(state, {
                    "event_type": "key_grant_revoked",
                    "occurred_at": now,
                    "actor": caller.id,
                    "request_id": f"ungrant-{key_id}-{signer_id}-{now}",
                    "payload": {"key_id": key_id, "caller_id": signer_id},
                })
            return {"key_id": key_id, "grantees":
                    [g for g in grantees if g != signer_id]}

    def list_grants(self) -> dict:
        return dict(self.store.state.get("key_grants", {}))

    # ------------------------------------------------------------ mutations
    def generate(
        self,
        caller: Caller,
        *,
        key_id: str | None = None,
        ttl: timedelta | None = DEFAULT_KEY_TTL,
        comment: str = "",
    ) -> dict:
        _require_key_admin(caller, "generate keys")
        key_id = key_id or f"key-{uuid.uuid4().hex[:12]}"
        now = utcnow_str(self.clock)
        with self.store.transaction() as state:
            if key_id in state["keys"]:
                raise KeyExistsError(
                    f"key '{key_id}' already exists",
                    details={"key_id": key_id},
                )
            expires_at = None
            if ttl is not None:
                from admission.clock import parse_ts

                expires_at = (parse_ts(now) + ttl).isoformat(timespec="seconds")
            record = KeyRecord(
                key_id=key_id,
                secret=generate_secret(),
                created_at=now,
                created_by=caller.id,
                expires_at=expires_at,
            )
            self.store.emit(state, {
                "event_type": "key_generated",
                "occurred_at": now,
                "actor": caller.id,
                "request_id": f"keygen-{key_id}-{now}",
                "payload": {"key": record.__dict__, "comment": comment},
            })
            return record.summary() | {"secret": record.secret}

    def rotate(self, caller: Caller, key_id: str, comment: str = "") -> dict:
        _require_key_admin(caller, "rotate keys")
        now = utcnow_str(self.clock)
        with self.store.transaction() as state:
            old_data = state["keys"].get(key_id)
            if old_data is None:
                    raise KeyNotFoundError(
                    f"cannot rotate unknown key '{key_id}'",
                    details={"key_id": key_id},
                )
            old = KeyRecord(**old_data)
            if old.revoked_at is not None:
                raise KeyRevokedError(
                    f"cannot rotate revoked key '{key_id}'",
                    details={"key_id": key_id, "revoked_reason": old.revoked_reason},
                )
            if old.rotated_at is not None:
                raise KeyRotatedError(
                    f"key '{key_id}' was already rotated to '{old.rotated_to}'",
                    details={"key_id": key_id, "rotated_to": old.rotated_to},
                )
            new_id = f"{key_id}-r{uuid.uuid4().hex[:8]}"
            new_record = KeyRecord(
                key_id=new_id,
                secret=generate_secret(),
                created_at=now,
                created_by=caller.id,
                expires_at=old.expires_at,
            )
            rotated_old = KeyRecord(
                **{**old.__dict__, "rotated_at": now, "rotated_to": new_id}
            )
            self.store.emit(state, {
                "event_type": "key_rotated",
                "occurred_at": now,
                "actor": caller.id,
                "request_id": f"rotate-{key_id}-{now}",
                "payload": {
                    "old_key": rotated_old.__dict__,
                    "new_key": new_record.__dict__,
                    "comment": comment,
                },
            })
            return {
                "rotated_from": rotated_old.summary(),
                "active_key": new_record.summary() | {"secret": new_record.secret},
            }

    def revoke(self, caller: Caller, key_id: str, reason: str = "") -> dict:
        _require_key_admin(caller, "revoke keys")
        now = utcnow_str(self.clock)
        with self.store.transaction() as state:
            old_data = state["keys"].get(key_id)
            if old_data is None:
                    raise KeyNotFoundError(
                    f"cannot revoke unknown key '{key_id}'",
                    details={"key_id": key_id},
                )
            old = KeyRecord(**old_data)
            if old.revoked_at is not None:
                return old.summary()  # revoke is idempotent
            revoked = KeyRecord(
                **{**old.__dict__, "revoked_at": now, "revoked_reason": reason or "manual"}
            )
            self.store.emit(state, {
                "event_type": "key_revoked",
                "occurred_at": now,
                "actor": caller.id,
                "request_id": f"revoke-{key_id}-{now}",
                "payload": {"key": revoked.__dict__, "reason": reason or "manual"},
            })
            return revoked.summary()
