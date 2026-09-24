"""Artifact signing and signature verification.

Signatures are HMAC-SHA256 over a canonical encoding of the artifact, bound
to the signer identity. Rules enforced here:

* Only callers holding the ``signer`` role may create a signature; everyone
  else gets ``unauthorized_caller`` and nothing is recorded.
* At most one signature per artifact digest exists. Concurrent or retried
  submissions return the already-stored record instead of registering a
  second, potentially contradictory one.
* Verification distinguishes the failure families: unknown key, revoked key,
  key rotated out since signing, signature past its expiry, and malformed or
  tampered signature bytes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable

from gate.errors import (
    KeyRevokedError,
    KeyUnknownError,
    SignatureExpiredError,
    SignatureInvalidError,
    UnauthorizedCallerError,
)
from gate.keystore import KeyStore
from gate.models import Artifact, Caller, SignatureRecord
from gate.storage import LocalStore

SIGNER_ROLE = "signer"
DEFAULT_SIGNATURE_TTL = 3600.0


class SigningService:
    def __init__(
        self,
        store: LocalStore,
        keys: KeyStore,
        clock: Callable[[], float] | None = None,
        signature_ttl: float | None = DEFAULT_SIGNATURE_TTL,
    ) -> None:
        self._store = store
        self._keys = keys
        self._clock = clock or self._keys.clock
        self._ttl = signature_ttl

    # -- signing ---------------------------------------------------------

    def sign(self, artifact: Artifact, caller: Caller) -> SignatureRecord:
        if SIGNER_ROLE not in caller.roles:
            raise UnauthorizedCallerError(
                f"caller {caller.identity!r} lacks role {SIGNER_ROLE!r}"
            )

        with self._store.lock:
            existing = self._store.signatures.get(artifact.digest)
            if existing is not None:
                # A signature already exists. A plain retry while the key is
                # still current returns the same record; after rotation (or
                # key changes) the request conflicts and must not overwrite.
                if existing.key_id != self._keys.active_key_id():
                    raise SignatureInvalidError(
                        "artifact already signed under key "
                        f"{existing.key_id!r}, which is no longer active"
                    )
                active = self._keys.get_active_key()
                expected = self._compute_mac(
                    active.secret, artifact, existing.caller
                )
                if not hmac.compare_digest(expected, existing.signature):
                    raise SignatureInvalidError(
                        "existing signature does not match the submitted artifact"
                    )
                return existing

            key = self._keys.get_active_key()
            now = self._clock()
            if key.expires_at is not None and key.expires_at <= now:
                raise SignatureInvalidError("active signing key is expired")
            expires_at = now + self._ttl if self._ttl is not None else None
            mac = self._compute_mac(key.secret, artifact, caller.identity)
            record = SignatureRecord(
                artifact_digest=artifact.digest,
                key_id=key.key_id,
                signature=mac,
                signed_at=now,
                expires_at=expires_at,
                caller=caller.identity,
            )
            self._store.signatures[artifact.digest] = record
            return record

    # -- verification ----------------------------------------------------

    def verify(
        self,
        artifact: Artifact,
        *,
        at: float | None = None,
    ) -> SignatureRecord:
        """Return the valid signature for ``artifact`` or raise a classified
        error. The check order is fixed so the reported reason is stable:
        missing -> unknown key -> revoked key -> rotated-out key ->
        expired -> tampered bytes.
        """
        now = self._clock() if at is None else at
        with self._store.lock:
            record = self._store.signatures.get(artifact.digest)
            if record is None:
                raise SignatureInvalidError("artifact has no registered signature")

            key = self._keys.get_key(record.key_id)
            if key is None:
                raise KeyUnknownError(f"key {record.key_id!r} is unknown")
            if key.revoked:
                raise KeyRevokedError(f"key {record.key_id!r} has been revoked")
            if self._keys.active_key_id() != record.key_id:
                raise SignatureInvalidError(
                    f"signature was made with rotated-out key {record.key_id!r}"
                )
            if record.expires_at is not None and record.expires_at <= now:
                raise SignatureExpiredError(
                    f"signature expired at {record.expires_at} (now {now})"
                )

            expected = self._compute_mac(key.secret, artifact, record.caller)
            if not hmac.compare_digest(expected, record.signature):
                raise SignatureInvalidError("signature does not match artifact")
            return record

    def get_record(self, artifact_digest: str) -> SignatureRecord | None:
        with self._store.lock:
            return self._store.signatures.get(artifact_digest)

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def canonical_message(artifact: Artifact, signer: str) -> bytes:
        body = {
            "digest": artifact.digest,
            "name": artifact.name,
            "kind": artifact.kind,
            "properties": artifact.properties,
            "signer": signer,
        }
        return json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def _compute_mac(
        self, secret: bytes, artifact: Artifact, signer: str
    ) -> bytes:
        return hmac.new(
            secret, self.canonical_message(artifact, signer), hashlib.sha256
        ).digest()
