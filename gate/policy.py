"""Policy version management and admission evaluation.

Version handling
----------------
Every publish creates an immutable, monotonically numbered
:class:`PolicyVersion`. Old versions are never deleted: evaluation may pin
``version`` to replay a historical decision, and rollback simply repoints the
"current" pointer at an older version while leaving the full history intact.

Evaluation semantics
--------------------
Rules are evaluated in list order; the first matching rule decides.

* matched rule effect ``deny``          -> DENY / policy_denied
* matched rule, caller lacks roles       -> DENY / unauthorized_caller
* matched rule, signature check fails    -> DENY / signature_* reason
* matched rule effect ``allow``          -> ALLOW
* matched rule effect ``review``         -> MANUAL_REVIEW
* no rule matches                         -> on_unmatched / policy_not_covered

The ``evaluation_id`` is a deterministic digest of (policy version, artifact
digest, caller identity), so the same inputs under the same policy version
yield the same id and the same conclusion.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from gate.errors import (
    KeyRevokedError,
    KeyUnknownError,
    PolicyNotFoundError,
    SignatureExpiredError,
    SignatureInvalidError,
)
from gate.models import (
    Artifact,
    Caller,
    Decision,
    DenyReason,
    EvaluationResult,
    PolicyRule,
    PolicyVersion,
)
from gate.signing import SigningService
from gate.storage import LocalStore

_SIGNATURE_REASON_MAP = {
    SignatureInvalidError: DenyReason.SIGNATURE_INVALID,
    SignatureExpiredError: DenyReason.SIGNATURE_EXPIRED,
    KeyRevokedError: DenyReason.KEY_REVOKED,
    KeyUnknownError: DenyReason.KEY_UNKNOWN,
}


class PolicyStore:
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

    # -- version management ---------------------------------------------

    def publish(
        self,
        rules: tuple[PolicyRule, ...] | list[PolicyRule],
        author: str,
        note: str = "",
        on_unmatched: Decision = Decision.MANUAL_REVIEW,
    ) -> PolicyVersion:
        rules = tuple(rules)
        with self._store.lock:
            version_no = len(self._store.policy_order) + 1
            policy = PolicyVersion(
                version=version_no,
                rules=rules,
                created_at=self._clock(),
                author=author,
                on_unmatched=on_unmatched,
                note=note,
            )
            self._store.policies[version_no] = policy
            self._store.policy_order.append(version_no)
            return policy

    def current(self) -> PolicyVersion | None:
        with self._store.lock:
            if not self._store.policy_order:
                return None
            return self._store.policies[self._store.policy_order[-1]]

    def current_version(self) -> int | None:
        policy = self.current()
        return policy.version if policy else None

    def get(self, version: int) -> PolicyVersion:
        with self._store.lock:
            policy = self._store.policies.get(version)
            if policy is None:
                raise PolicyNotFoundError(f"policy version {version} not found")
            return policy

    def resolve(self, version: int | None) -> PolicyVersion:
        if version is not None:
            return self.get(version)
        policy = self.current()
        if policy is None:
            raise PolicyNotFoundError("no policy has been published")
        return policy

    def list_versions(self) -> list[PolicyVersion]:
        with self._store.lock:
            return [self._store.policies[v] for v in self._store.policy_order]


class PolicyEvaluator:
    def __init__(
        self,
        signing: SigningService | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._signing = signing
        if clock is not None:
            self._clock = clock
        else:
            import time

            self._clock = time.time

    def evaluate(
        self,
        policy: PolicyVersion,
        artifact: Artifact,
        caller: Caller,
        *,
        at: float | None = None,
    ) -> EvaluationResult:
        now = self._clock() if at is None else at
        evaluation_id = self._evaluation_id(policy, artifact, caller)

        for rule in policy.rules:
            if not rule.matches(artifact):
                continue

            # Authorization is checked before the effect, so a forbidden
            # caller is denied even when the rule would otherwise allow.
            if rule.require_roles and caller.roles.isdisjoint(rule.require_roles):
                return EvaluationResult(
                    decision=Decision.DENY,
                    reason=DenyReason.UNAUTHORIZED_CALLER.value,
                    policy_version=policy.version,
                    rationale=(
                        f"rule {rule.name!r} matches but caller "
                        f"{caller.identity!r} lacks any required role "
                        f"{sorted(rule.require_roles)}"
                    ),
                    evaluation_id=evaluation_id,
                    matched_rule=rule.name,
                )

            if rule.require_signature:
                try:
                    record = self._signing.verify(artifact, at=now)
                except (
                    SignatureInvalidError,
                    SignatureExpiredError,
                    KeyRevokedError,
                    KeyUnknownError,
                ) as exc:
                    reason = _SIGNATURE_REASON_MAP[type(exc)]
                    return EvaluationResult(
                        decision=Decision.DENY,
                        reason=reason.value,
                        policy_version=policy.version,
                        rationale=(
                            f"rule {rule.name!r} requires a valid signature: "
                            f"{exc}"
                        ),
                        evaluation_id=evaluation_id,
                        matched_rule=rule.name,
                    )
                fingerprint = record.fingerprint()
            else:
                fingerprint = None

            if rule.effect.value == Decision.ALLOW.value:
                return EvaluationResult(
                    decision=Decision.ALLOW,
                    reason=None,
                    policy_version=policy.version,
                    rationale=f"rule {rule.name!r} matched and allowed the artifact",
                    evaluation_id=evaluation_id,
                    matched_rule=rule.name,
                    signature_fingerprint=fingerprint,
                )
            if rule.effect.value == Decision.DENY.value:
                return EvaluationResult(
                    decision=Decision.DENY,
                    reason=DenyReason.POLICY_DENIED.value,
                    policy_version=policy.version,
                    rationale=f"rule {rule.name!r} explicitly denies the artifact",
                    evaluation_id=evaluation_id,
                    matched_rule=rule.name,
                    signature_fingerprint=fingerprint,
                )
            return EvaluationResult(
                decision=Decision.MANUAL_REVIEW,
                reason=None,
                policy_version=policy.version,
                rationale=f"rule {rule.name!r} routes the artifact to manual review",
                evaluation_id=evaluation_id,
                matched_rule=rule.name,
                signature_fingerprint=fingerprint,
            )

        return EvaluationResult(
            decision=policy.on_unmatched,
            reason=DenyReason.POLICY_NOT_COVERED.value,
            policy_version=policy.version,
            rationale="no rule in the active policy matches this artifact",
            evaluation_id=evaluation_id,
        )

    @staticmethod
    def _evaluation_id(
        policy: PolicyVersion, artifact: Artifact, caller: Caller
    ) -> str:
        h = hashlib.sha256()
        h.update(f"v{policy.version}".encode())
        h.update(b"|")
        h.update(artifact.digest.encode())
        h.update(b"|")
        h.update(caller.identity.encode())
        return "eval-" + h.hexdigest()[:20]
