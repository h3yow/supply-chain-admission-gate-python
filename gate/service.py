"""Application service orchestrating keys, signatures, policy and audit.

Concurrency model: every public write/evaluate path takes the single store
lock for its whole critical section. Duplicate submission therefore maps to
the single stored signature record, and audit events are appended in the same
critical section as the change they describe -- no partial state, no missing
journal entries.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable

from gate.audit import AuditLog
from gate.keystore import KeyStore
from gate.models import (
    Artifact,
    Caller,
    Decision,
    EvaluationResult,
    PolicyRule,
    SignatureRecord,
)
from gate.policy import PolicyEvaluator, PolicyStore
from gate.signing import SigningService
from gate.storage import LocalStore

logger = logging.getLogger("gate")


class AdmissionService:
    def __init__(
        self,
        store: LocalStore | None = None,
        clock: Callable[[], float] | None = None,
        signature_ttl: float | None = 3600.0,
    ) -> None:
        if clock is None:
            import time

            clock = time.time
        self._clock = clock
        self.store = store or LocalStore()
        self.keys = KeyStore(self.store, clock=clock)
        self.signing = SigningService(
            self.store, self.keys, clock=clock, signature_ttl=signature_ttl
        )
        self.policies = PolicyStore(self.store, clock=clock)
        self.evaluator = PolicyEvaluator(self.signing, clock=clock)
        self.audit = AuditLog(self.store, clock=clock)

    # -- keys ------------------------------------------------------------

    def bootstrap_key(self) -> str:
        with self.store.lock:
            if self.store.active_key_id is not None:
                return self.store.active_key_id
            key_id = self.keys.generate_key()
            self.audit.append("key.generated", {"key_id": key_id})
            return key_id

    def rotate_key(self) -> str:
        with self.store.lock:
            key_id = self.keys.rotate_key()
            self.audit.append("key.rotated", {"key_id": key_id})
            return key_id

    def revoke_key(self, key_id: str) -> None:
        with self.store.lock:
            self.keys.revoke_key(key_id)
            self.audit.append("key.revoked", {"key_id": key_id})

    # -- policy ----------------------------------------------------------

    def publish_policy(
        self,
        rules: list[PolicyRule] | tuple[PolicyRule, ...],
        author: str,
        note: str = "",
        on_unmatched: Decision = Decision.MANUAL_REVIEW,
    ) -> int:
        with self.store.lock:
            policy = self.policies.publish(
                tuple(rules), author=author, note=note, on_unmatched=on_unmatched
            )
            self.audit.append(
                "policy.published",
                {
                    "version": policy.version,
                    "author": author,
                    "rule_count": len(policy.rules),
                    "rule_names": [r.name for r in policy.rules],
                    "on_unmatched": policy.on_unmatched.value,
                    "note": note,
                },
            )
            return policy.version

    def rollback_policy(self, target_version: int, author: str) -> int:
        """Re-publish an older version's rules as a brand-new version.

        The version chain stays append-only and complete; the rollback itself
        is audited with both the source and the new version numbers.
        """
        with self.store.lock:
            source = self.policies.get(target_version)
            new = self.policies.publish(
                source.rules,
                author=author,
                note=f"rollback to v{target_version}",
                on_unmatched=source.on_unmatched,
            )
            self.audit.append(
                "policy.rolled_back",
                {
                    "from_version": target_version,
                    "new_version": new.version,
                    "author": author,
                },
            )
            return new.version

    # -- signatures ------------------------------------------------------

    def submit_signature(
        self, artifact: Artifact, caller: Caller
    ) -> tuple[SignatureRecord, bool]:
        """Sign an artifact. Returns ``(record, created)`` -- ``created`` is
        False when the caller hit an already-registered signature (retry or
        concurrent duplicate). A rejected attempt (e.g. non-signer) is
        audited and re-raised without mutating any state."""
        with self.store.lock:
            already = self.store.signatures.get(artifact.digest)
            try:
                record = self.signing.sign(artifact, caller)
            except Exception as exc:
                self.audit.append(
                    "signature.rejected",
                    {
                        "artifact_digest": artifact.digest,
                        "caller": caller.identity,
                        "reason": getattr(exc, "code", "error"),
                    },
                )
                raise
            created = already is None
            self.audit.append(
                "signature.submitted",
                {
                    "artifact_digest": artifact.digest,
                    "caller": caller.identity,
                    "key_id": record.key_id,
                    "created": created,
                    "fingerprint": record.fingerprint(),
                },
            )
            logger.info(
                "signature submit | artifact=%s caller=%s created=%s key=%s",
                artifact.digest,
                caller.identity,
                created,
                record.key_id,
            )
            return record, created

    # -- evaluation ------------------------------------------------------

    def evaluate(
        self,
        artifact: Artifact,
        caller: Caller,
        policy_version: int | None = None,
        at: float | None = None,
    ) -> EvaluationResult:
        with self.store.lock:
            policy = self.policies.resolve(policy_version)
            result = self.evaluator.evaluate(policy, artifact, caller, at=at)
            self.audit.append(
                "admission.evaluated",
                {
                    "evaluation_id": result.evaluation_id,
                    "artifact_digest": artifact.digest,
                    "artifact_summary": artifact.summary(),
                    "caller": caller.summary(),
                    "policy_version": result.policy_version,
                    "decision": result.decision.value,
                    "reason": result.reason,
                    "matched_rule": result.matched_rule,
                    "rationale": result.rationale,
                },
            )
            logger.info(
                "admission eval | input=%s decision=%s reason=%s policy=v%s "
                "rule=%s rationale=%s",
                json.dumps(
                    {
                        "digest": artifact.digest,
                        "kind": artifact.kind,
                        "caller": caller.identity,
                        "roles": sorted(caller.roles),
                    },
                    sort_keys=True,
                ),
                result.decision.value,
                result.reason,
                result.policy_version,
                result.matched_rule,
                result.rationale,
            )
            return result

    # -- introspection ---------------------------------------------------

    def audit_events(self, event_type: str | None = None) -> list[dict]:
        return [e.to_dict() for e in self.audit.events(event_type)]
