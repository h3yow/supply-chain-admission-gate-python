"""Artifact signing and multi-signature validity/quorum evaluation.

One artifact may carry many independent signatures, each identified by
``(artifact_digest, signed_by, key_id)``. Re-submission by the same signing
party with the same key (retry, duplicate or concurrent race) collapses onto
the original record and returns it with ``dedup=True``; it never creates a
second record and never counts twice. A *different* signer or a *different*
key for the same artifact is a new, independent signature.

Per-signature status (deterministic, given a point in time and the key
registry):

* ``unauthorized_caller`` -> signer identity lost its server-side grant
* ``invalid``    -> HMAC does not verify (tampered payload or wrong secret)
* ``revoked``    -> the signing key has been revoked
* ``rotated``    -> the signing key has been rotated away; every signature
                    made with it stops counting (re-sign with the successor)
* ``expired``    -> signature TTL elapsed
* ``valid``      -> all checks pass

Quorum evaluation (``evaluate_signatures``) counts only ``valid`` signatures,
deduplicated by signing party *and* by key: one party cannot fill the quorum
alone, and one key cannot either. The aggregate status is:

* ``missing``        -> no signature registered at all
* ``quorum_not_met`` -> at least one valid signature, but fewer than required
* ``valid``          -> counted distinct parties >= required
* otherwise          -> no valid signature; the most severe per-signature
                        status (fixed priority: invalid, revoked,
                        unauthorized_caller, rotated, expired)

Concurrency: registration is idempotent per ``request_id`` and per
``(artifact, signer, key)`` under the store lock, so concurrent/retry
submissions all observe the same single record.
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
from admission.replay import signature_record_key
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
    "quorum_not_met": DenyReason.SIGNATURE_QUORUM_NOT_MET,
}

# Fixed severity order used to pick the aggregate status when no signature is
# valid at all. Deterministic so the same facts always yield the same reason.
_FAILURE_PRIORITY = ("invalid", "revoked", "unauthorized_caller",
                     "rotated", "expired")


class SigningService:
    def __init__(self, store: Store, clock: Clock, keys: KeyService) -> None:
        self.store = store
        self.clock = clock
        self.keys = keys

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _find_record(state: dict, artifact_digest: str, key_id: str,
                     signer_id: str) -> dict | None:
        per_artifact = state["signatures"].get(artifact_digest, {})
        return per_artifact.get(f"{signer_id}:{key_id}")

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
                    record = self._find_record(state, digest, key_id, caller.id) \
                        if digest == artifact_digest else None
                    if record is not None:
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

            # 2) signer+key dedup: the same party re-signing the same artifact
            #    with the same key (retry/concurrent duplicate under a new
            #    request_id) returns the original record and never counts
            #    twice. Other signers/keys on the same artifact are unaffected.
            record = self._find_record(state, artifact_digest, key_id, caller.id)
            if record is not None:
                self.store.emit(state, {
                    "event_type": "signature_dedup_hit",
                    "occurred_at": now,
                    "actor": caller.id,
                    "request_id": request_id,
                    "payload": {
                        "artifact_digest": artifact_digest,
                        "record_key": signature_record_key(record),
                    },
                })
                return SignatureRecord(**record).summary() | {"dedup": True}

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
    def _check_record(self, record: SignatureRecord, artifact_type: str,
                      now) -> str:
        """Status of one signature record against current time and registry."""
        key_data = self.store.state["keys"].get(record.key_id)
        if key_data is None:  # registered key vanished (cannot happen locally)
            return "invalid"

        # Tampering / secret mismatch first: a rotated/revoked key that no
        # longer verifies is fundamentally invalid, not merely stale.
        if not verify(key_data["secret"],
                      canonical_payload(record.artifact_digest, artifact_type),
                      record.signature):
            return "invalid"

        # A signer whose grant is later revoked loses signature validity:
        # authorization is re-evaluated against the authoritative registry.
        if record.signed_by not in self.store.state.get("key_grants", {}).get(
                record.key_id, []):
            return "unauthorized_caller"

        if key_data["revoked_at"] is not None:
            # Revocation is immediate and applies retroactively.
            return "revoked"

        if key_data["rotated_at"] is not None:
            # Rotation retires the key: every signature made with it stops
            # counting, whenever it was created. The record is kept for
            # audit, and the signer may re-sign with the successor key.
            return "rotated"

        if record.expires_at is not None and now >= parse_ts(record.expires_at):
            return "expired"

        return "valid"

    def evaluate_signatures(self, artifact_digest: str, artifact_type: str,
                            required: int = 1) -> dict:
        """Quorum report over every signature registered for the artifact.

        Pure with respect to current clock + store state. Only ``valid``
        signatures count, deduplicated by signing party and by key: the first
        valid signature (in deterministic signed_at order) claims its signer
        and key; later valid signatures reusing either are reported but not
        counted.
        """
        now = self.clock.now()
        per_artifact = self.store.state["signatures"].get(artifact_digest, {})
        records = sorted(
            (SignatureRecord(**data) for data in per_artifact.values()),
            key=lambda r: (r.signed_at, r.key_id, r.signed_by),
        )

        entries: list[dict] = []
        seen_signers: set[str] = set()
        seen_keys: set[str] = set()
        counted = 0
        for record in records:
            status = self._check_record(record, artifact_type, now)
            entry = {
                "signature": record.summary(),
                "status": status,
                "reason": None if status == "valid"
                          else STATUS_TO_REASON[status].value,
                "counted": False,
                "not_counted_reason": None,
            }
            if status == "valid":
                if record.signed_by in seen_signers:
                    entry["not_counted_reason"] = "duplicate_signer"
                elif record.key_id in seen_keys:
                    entry["not_counted_reason"] = "duplicate_key"
                else:
                    seen_signers.add(record.signed_by)
                    seen_keys.add(record.key_id)
                    counted += 1
                    entry["counted"] = True
            else:
                entry["not_counted_reason"] = entry["reason"]
            entries.append(entry)

        required = max(1, required)
        if not entries:
            status, reason = "missing", STATUS_TO_REASON["missing"].value
        elif counted >= required:
            status, reason = "valid", None
        elif counted >= 1:
            status = "quorum_not_met"
            reason = STATUS_TO_REASON["quorum_not_met"].value
        else:
            status = next(s for s in _FAILURE_PRIORITY
                          if any(e["status"] == s for e in entries))
            reason = STATUS_TO_REASON[status].value

        representative = entries[0]["signature"] if entries else None
        return {
            "artifact_digest": artifact_digest,
            "required": required,
            "counted": counted,
            "missing": max(0, required - counted),
            "entries": entries,
            "signature": representative,
            "status": status,
            "reason": reason,
        }

    def validate_signature(
        self, artifact_digest: str, artifact_type: str
    ) -> tuple[dict | None, str | None, str | None]:
        """Single-signature view kept for callers of the original API.

        Equivalent to ``evaluate_signatures(..., required=1)``: returns
        ``(representative_signature_or_None, status, deny_reason_or_None)``.
        """
        report = self.evaluate_signatures(artifact_digest, artifact_type,
                                          required=1)
        return report["signature"], report["status"], report["reason"]

    # -------------------------------------------------------------- query
    def list_signatures(self, artifact_digest: str) -> list[dict]:
        per_artifact = self.store.state["signatures"].get(artifact_digest, {})
        if not per_artifact:
            raise SignatureNotFoundError(
                f"no signature registered for artifact '{artifact_digest}'",
                details={"artifact_digest": artifact_digest},
            )
        records = sorted(
            (SignatureRecord(**data) for data in per_artifact.values()),
            key=lambda r: (r.signed_at, r.key_id, r.signed_by),
        )
        return [r.summary() for r in records]

    def get_signature(self, artifact_digest: str) -> dict:
        return {"artifact_digest": artifact_digest,
                "signatures": self.list_signatures(artifact_digest)}
