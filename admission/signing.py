"""Artifact signing and signature validity checks.

Signature status (deterministic, given a point in time and the key registry):

* ``missing``    -> no signature registered for the artifact
* ``unauthorized_caller`` -> signer identity was not granted that key
* ``invalid``    -> HMAC does not verify (tampered payload or wrong secret)
* ``revoked``    -> the signing key has been revoked
* ``rotated``    -> signature was created with a key after it was rotated
                    (a pre-rotation signature is only ``expired`` if old)
* ``expired``    -> signature TTL elapsed
* ``valid``      -> all checks pass

Concurrency: registration is idempotent per ``request_id`` and single-flight
per artifact digest (store lock). Concurrent/retry submissions either all
receive the same record (same request_id) or one wins while others get a
stable ``idempotency_conflict`` (different request_id, same artifact).
"""
from __future__ import annotations

from datetime import timedelta

from admission.clock import Clock, parse_ts, utcnow_str
from admission.crypto import canonical_payload, sign, verify
from admission.keys import KeyService
from admission.models import (
    Caller,
    DenyReason,
    IdempotencyConflictError,
    SignatureNotFoundError,
    SignatureRecord,
)
from admission.storage import Store

SIGNER_ROLE = "signer"
DEFAULT_SIGNATURE_TTL = timedelta(days=30)

STATUS_TO_REASON = {
    "missing": DenyReason.SIGNATURE_MISSING,
    "invalid": DenyReason.SIGNATURE_INVALID,
    "expired": DenyReason.SIGNATURE_EXPIRED,
    "rotated": DenyReason.SIGNATURE_KEY_ROTATED,
    "revoked": DenyReason.SIGNATURE_KEY_REVOKED,
    "unauthorized_caller": DenyReason.SIGNATURE_UNAUTHORIZED_CALLER,
}


class SigningService:
    def __init__(self, store: Store, clock: Clock, keys: KeyService) -> None:
        self.store = store
        self.clock = clock
        self.keys = keys

    # ------------------------------------------------------------ register
    def sign_artifact(
        self,
        caller: Caller,
        *,
        artifact_digest: str,
        artifact_type: str,
        key_id: str,
        request_id: str,
        signature_ttl: timedelta | None = DEFAULT_SIGNATURE_TTL,
    ) -> dict:
        if not caller.has_role(SIGNER_ROLE):
            from admission.keys import PermissionDeniedError

            raise PermissionDeniedError(
                f"caller '{caller.id}' lacks role '{SIGNER_ROLE}' required to sign",
                details={"caller": caller.summary(), "required_role": SIGNER_ROLE},
            )

        now = utcnow_str(self.clock)
        with self.store.transaction() as state:
            # 1) request_id dedup: retries return the original result.
            existing_idx = state["request_index"].get(request_id)
            if existing_idx is not None:
                if existing_idx["kind"] in ("sign", "sign_dedup"):
                    digest = existing_idx["result_key"]
                    record = state["signatures"].get(digest)
                    if record is not None and digest == artifact_digest:
                        self.store.emit(state, {
                            "event_type": "signature_dedup_hit",
                            "occurred_at": now,
                            "actor": caller.id,
                            "request_id": request_id,
                            "payload": {"artifact_digest": artifact_digest,
                                       "original_seq": existing_idx["seq"]},
                        })
                        return SignatureRecord(**record).summary() | {"dedup": True}
                raise IdempotencyConflictError(
                    f"request_id '{request_id}' was already used for a different request",
                    details={"request_id": request_id, "existing": existing_idx},
                )

            # 2) single-flight per artifact: one signature, never contradicted.
            if artifact_digest in state["signatures"]:
                raise IdempotencyConflictError(
                    f"artifact '{artifact_digest}' already has a registered signature; "
                    "re-sign with the original request_id or rotate the key first",
                    details={"artifact_digest": artifact_digest},
                )

            # 3) key must exist and be currently active.
            key_data = state["keys"].get(key_id)
            if key_data is None:
                from admission.models import KeyNotFoundError

                raise KeyNotFoundError(
                    f"cannot sign with unknown key '{key_id}'",
                    details={"key_id": key_id},
                )
            if key_data["revoked_at"] is not None:
                from admission.models import KeyRevokedError

                raise KeyRevokedError(
                    f"cannot sign with revoked key '{key_id}'",
                    details={"key_id": key_id},
                )
            if key_data["rotated_at"] is not None:
                from admission.models import KeyRotatedError

                raise KeyRotatedError(
                    f"cannot sign with rotated key '{key_id}'; use '{key_data['rotated_to']}'",
                    details={"key_id": key_id, "rotated_to": key_data["rotated_to"]},
                )

            # 4) caller must be authorized to use this key. Two independent
            #    checks: the request token claims the grant, and the server
            #    registry (managed by key admins) confirms it.
            from admission.keys import PermissionDeniedError

            if key_id not in caller.key_grants:
                raise PermissionDeniedError(
                    f"caller '{caller.id}' request is not authorized for key '{key_id}'",
                    details={"caller": caller.summary(), "key_id": key_id},
                )
            if caller.id not in state["key_grants"].get(key_id, []):
                raise PermissionDeniedError(
                    f"caller '{caller.id}' has no server-side grant for key '{key_id}'",
                    details={"caller": caller.summary(), "key_id": key_id},
                )

            expires_at = None
            if signature_ttl is not None:
                expires_at = (parse_ts(now) + signature_ttl).isoformat(timespec="seconds")
            signature = sign(key_data["secret"],
                             canonical_payload(artifact_digest, artifact_type))
            record = SignatureRecord(
                artifact_digest=artifact_digest,
                key_id=key_id,
                signature=signature,
                signed_at=now,
                signed_by=caller.id,
                expires_at=expires_at,
            )
            self.store.emit(state, {
                "event_type": "signature_registered",
                "occurred_at": now,
                "actor": caller.id,
                "request_id": request_id,
                "payload": {"signature": record.__dict__, "artifact_type": artifact_type},
            })
            return record.summary() | {"dedup": False}

    # ------------------------------------------------------------ validate
    def validate_signature(
        self, artifact_digest: str, artifact_type: str
    ) -> tuple[dict | None, str | None, str | None]:
        """Return ``(signature_summary_or_None, status, deny_reason_or_None)``.

        Pure with respect to current clock + store state. Ordering of checks is
        fixed so the returned reason is stable and explainable.
        """
        now = self.clock.now()
        record_data = self.store.state["signatures"].get(artifact_digest)
        if record_data is None:
            return None, "missing", DenyReason.SIGNATURE_MISSING.value

        record = SignatureRecord(**record_data)
        summary = record.summary()

        def bad(status: str) -> tuple[dict, str, str]:
            return summary, status, STATUS_TO_REASON[status].value

        key_data = self.store.state["keys"].get(record.key_id)
        if key_data is None:  # registered key vanished (cannot happen locally)
            return bad("invalid")
        key = type("K", (), key_data)  # lightweight attribute view

        # Tampering / secret mismatch first: a rotated/revoked key that no
        # longer verifies is fundamentally invalid, not merely stale.
        if not verify(key.secret,
                      canonical_payload(artifact_digest, artifact_type),
                      record.signature):
            return bad("invalid")

        # A signer whose grant is later revoked loses signature validity:
        # authorization is re-evaluated against the authoritative registry.
        if record.signed_by not in self.store.state.get("key_grants", {}).get(record.key_id, []):
            return bad("unauthorized_caller")

        if key.revoked_at is not None:
            # Revocation is immediate and applies retroactively.
            return bad("revoked")

        if key.rotated_at is not None and parse_ts(record.signed_at) > parse_ts(key.rotated_at):
            # Signed with the old key strictly *after* rotation happened.
            # Equality cannot occur post-rotation: such a registration is
            # rejected under the same serialised transaction that performed
            # the rotation, so equal timestamps mean the signature committed
            # first and remains a legitimate pre-rotation signature.
            return bad("rotated")

        if record.expires_at is not None and now >= parse_ts(record.expires_at):
            return bad("expired")

        return summary, "valid", None

    def get_signature(self, artifact_digest: str) -> dict:
        data = self.store.state["signatures"].get(artifact_digest)
        if data is None:
            raise SignatureNotFoundError(
                f"no signature registered for artifact '{artifact_digest}'",
                details={"artifact_digest": artifact_digest},
            )
        return SignatureRecord(**data).summary()
