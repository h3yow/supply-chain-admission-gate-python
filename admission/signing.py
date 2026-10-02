"""Artifact signing and signature validity checks.

Multi-signature model: one artifact may carry many signatures, each from a
distinct (signer, key) pair. The pair is the dedup identity ("slot"): the same
signer re-submitting with the same key for the same artifact — retry, duplicate
or concurrent — always yields the original record and never a second entry,
while a *different* signer or a *different* key (e.g. after rotation) is
accepted as an independent signature.

Signature status (deterministic, given a point in time and the key registry):

* ``missing``    -> no signature registered for the artifact
* ``unauthorized_caller`` -> signer identity was not granted that key
* ``invalid``    -> HMAC does not verify (tampered payload or wrong secret)
* ``revoked``    -> the signing key has been revoked
* ``rotated``    -> signature was created with a key after it was rotated
                    (a pre-rotation signature is only ``expired`` if old)
* ``expired``    -> signature TTL elapsed
* ``valid``      -> all checks pass

Concurrency: registration is idempotent per ``request_id`` and per
(artifact, signer, key) slot under the store lock. Concurrent/retry
submissions either replay the original record (same request_id) or dedup onto
the existing slot (same signer+key); both are recorded as
``signature_dedup_hit`` so replays rebuild the identical state.
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
from admission.replay import signature_slot
from admission.storage import Store

SIGNER_ROLE = "signer"
DEFAULT_SIGNATURE_TTL = timedelta(days=30)


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
        slot = signature_slot({"signed_by": caller.id, "key_id": key_id})
        with self.store.transaction() as state:
            # 1) request_id dedup: retries return the original result.
            existing_idx = state["request_index"].get(request_id)
            if existing_idx is not None:
                if existing_idx["kind"] in ("sign", "sign_dedup"):
                    digest = existing_idx["result_key"]
                    record = state["signatures"].get(digest, {}).get(
                        existing_idx.get("slot", ""))
                    if record is not None and digest == artifact_digest:
                        self.store.emit(state, {
                            "event_type": "signature_dedup_hit",
                            "occurred_at": now,
                            "actor": caller.id,
                            "request_id": request_id,
                            "payload": {"artifact_digest": artifact_digest,
                                       "slot": existing_idx["slot"],
                                       "original_seq": existing_idx["seq"]},
                        })
                        return SignatureRecord(**record).summary() | {"dedup": True}
                raise IdempotencyConflictError(
                    f"request_id '{request_id}' was already used for a different request",
                    details={"request_id": request_id, "existing": existing_idx},
                )

            # 2) slot dedup: the same signer re-submitting with the same key
            #    for this artifact (retry / duplicate / concurrent, different
            #    request_id) gets the original record back; it never becomes a
            #    second signature. Other signers/keys are unaffected.
            existing = state["signatures"].get(artifact_digest, {}).get(slot)
            if existing is not None:
                self.store.emit(state, {
                    "event_type": "signature_dedup_hit",
                    "occurred_at": now,
                    "actor": caller.id,
                    "request_id": request_id,
                    "payload": {"artifact_digest": artifact_digest,
                               "slot": slot,
                               "original_seq": None},
                })
                return SignatureRecord(**existing).summary() | {"dedup": True}

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
    def _classify(
        self, record: SignatureRecord, artifact_type: str, now
    ) -> tuple[str, str | None]:
        """Status + deny reason for one record. Fixed check order so the
        returned reason is stable and explainable."""
        key_data = self.store.state["keys"].get(record.key_id)
        if key_data is None:  # registered key vanished (cannot happen locally)
            return "invalid", DenyReason.SIGNATURE_INVALID.value
        key = type("K", (), key_data)  # lightweight attribute view

        # Tampering / secret mismatch first: a rotated/revoked key that no
        # longer verifies is fundamentally invalid, not merely stale.
        if not verify(key.secret,
                      canonical_payload(record.artifact_digest, artifact_type),
                      record.signature):
            return "invalid", DenyReason.SIGNATURE_INVALID.value

        # A signer whose grant is later revoked loses signature validity:
        # authorization is re-evaluated against the authoritative registry.
        if record.signed_by not in self.store.state.get("key_grants", {}).get(record.key_id, []):
            return "unauthorized_caller", DenyReason.SIGNATURE_UNAUTHORIZED_CALLER.value

        if key.revoked_at is not None:
            # Revocation is immediate and applies retroactively.
            return "revoked", DenyReason.SIGNATURE_KEY_REVOKED.value

        if key.rotated_at is not None and parse_ts(record.signed_at) > parse_ts(key.rotated_at):
            # Signed with the old key strictly *after* rotation happened.
            # Equality cannot occur post-rotation: such a registration is
            # rejected under the same serialised transaction that performed
            # the rotation, so equal timestamps mean the signature committed
            # first and remains a legitimate pre-rotation signature.
            return "rotated", DenyReason.SIGNATURE_KEY_ROTATED.value

        if record.expires_at is not None and now >= parse_ts(record.expires_at):
            return "expired", DenyReason.SIGNATURE_EXPIRED.value

        return "valid", None

    def validate_signatures(
        self, artifact_digest: str, artifact_type: str
    ) -> list[dict]:
        """Classify every signature registered for the artifact.

        Returns a deterministically ordered list of
        ``{"signature": summary, "status": str, "reason": str|None}`` —
        one entry per (signer, key) slot, valid and invalid alike, so the
        admission engine can account for each one. Pure with respect to the
        current clock + store state.
        """
        now = self.clock.now()
        records = [
            SignatureRecord(**data)
            for data in self.store.state["signatures"].get(artifact_digest, {}).values()
        ]
        records.sort(key=lambda r: (r.signed_at, r.key_id, r.signed_by))
        out = []
        for record in records:
            status, reason = self._classify(record, artifact_type, now)
            out.append({"signature": record.summary(),
                        "status": status, "reason": reason})
        return out

    def validate_signature(
        self, artifact_digest: str, artifact_type: str
    ) -> tuple[dict | None, str | None, str | None]:
        """Single-signature view kept for callers of the original API.

        Returns ``(signature_summary_or_None, status, deny_reason_or_None)``
        for the representative record: the first valid one if any, else the
        first registered (deterministic order).
        """
        entries = self.validate_signatures(artifact_digest, artifact_type)
        if not entries:
            return None, "missing", DenyReason.SIGNATURE_MISSING.value
        for entry in entries:
            if entry["status"] == "valid":
                return entry["signature"], "valid", None
        first = entries[0]
        return first["signature"], first["status"], first["reason"]

    def get_signatures(self, artifact_digest: str) -> dict:
        """All signatures registered for the artifact (history preserved)."""
        records = self.store.state["signatures"].get(artifact_digest, {})
        if not records:
            raise SignatureNotFoundError(
                f"no signature registered for artifact '{artifact_digest}'",
                details={"artifact_digest": artifact_digest},
            )
        summaries = [SignatureRecord(**data).summary()
                     for data in records.values()]
        summaries.sort(key=lambda s: (s["signed_at"], s["key_id"], s["signed_by"]))
        return {"artifact_digest": artifact_digest, "signatures": summaries}
