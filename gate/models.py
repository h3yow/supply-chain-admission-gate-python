"""Domain data models for the supply-chain admission gate.

The model intentionally keeps only what is needed to distinguish the three
denial families required by the admission semantics:

* ``unauthorized_caller`` -- the artifact is covered by policy but the
  caller's identity/roles are insufficient.
* ``policy_not_covered`` -- no rule in the active policy covers the
  artifact at all.
* ``policy_denied`` -- a matching rule explicitly forbids the artifact.

Signature-related reasons (invalid/expired/revoked/unknown key) are tracked
separately because a signature failure must never look like a policy denial.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    MANUAL_REVIEW = "manual_review"


class RuleEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REVIEW = "review"


class DenyReason(str, Enum):
    UNAUTHORIZED_CALLER = "unauthorized_caller"
    POLICY_NOT_COVERED = "policy_not_covered"
    POLICY_DENIED = "policy_denied"
    SIGNATURE_INVALID = "signature_invalid"
    SIGNATURE_EXPIRED = "signature_expired"
    KEY_REVOKED = "key_revoked"
    KEY_UNKNOWN = "key_unknown"


@dataclass(frozen=True)
class Artifact:
    """A deployable artifact identified by its content digest."""

    digest: str
    name: str
    kind: str
    properties: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "name": self.name,
            "kind": self.kind,
            "properties": dict(self.properties),
        }


@dataclass(frozen=True)
class Caller:
    """An authenticated API caller with a set of granted roles."""

    identity: str
    roles: frozenset[str] = frozenset()

    def summary(self) -> dict[str, Any]:
        return {"identity": self.identity, "roles": sorted(self.roles)}


@dataclass
class StoredKey:
    """A local HMAC signing key. Old keys are retained (rotated), not
    deleted, so historical signatures can still be explained."""

    key_id: str
    secret: bytes
    created_at: float
    expires_at: float | None
    revoked: bool = False


@dataclass(frozen=True)
class SignatureRecord:
    artifact_digest: str
    key_id: str
    signature: bytes
    signed_at: float
    expires_at: float | None
    caller: str

    def fingerprint(self) -> str:
        import hashlib

        h = hashlib.sha256()
        h.update(self.artifact_digest.encode())
        h.update(self.key_id.encode())
        h.update(str(self.signed_at).encode())
        h.update(self.signature)
        return h.hexdigest()[:16]


@dataclass(frozen=True)
class PolicyRule:
    """A single ordered policy rule.

    * ``artifact_kinds`` -- artifact kinds this rule matches ("*" = any).
    * ``property_match`` -- all key/value pairs must equal artifact props.
    * ``require_roles`` -- caller needs at least one of these roles; an
      empty set means any authenticated caller is acceptable.
    * ``effect`` -- allow / deny / manual review when the rule matches.
    * ``require_signature`` -- a currently-valid signature must exist.
    """

    name: str
    artifact_kinds: frozenset[str]
    effect: RuleEffect
    require_roles: frozenset[str] = frozenset()
    require_signature: bool = False
    property_match: dict[str, Any] = field(default_factory=dict)

    def matches(self, artifact: Artifact) -> bool:
        if "*" not in self.artifact_kinds and artifact.kind not in self.artifact_kinds:
            return False
        for key, value in self.property_match.items():
            if artifact.properties.get(key) != value:
                return False
        return True


@dataclass(frozen=True)
class PolicyVersion:
    """An immutable, numbered revision of the ordered rule list.

    ``on_unmatched`` decides the conclusion when *no* rule matches; the
    reason recorded is always ``policy_not_covered`` regardless of effect.
    """

    version: int
    rules: tuple[PolicyRule, ...]
    created_at: float
    author: str
    on_unmatched: Decision = Decision.MANUAL_REVIEW
    note: str = ""


@dataclass(frozen=True)
class EvaluationResult:
    decision: Decision
    reason: str | None
    policy_version: int | None
    rationale: str
    evaluation_id: str
    matched_rule: str | None = None
    signature_fingerprint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "rationale": self.rationale,
            "evaluation_id": self.evaluation_id,
            "matched_rule": self.matched_rule,
            "signature_fingerprint": self.signature_fingerprint,
        }


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp: float
    event_type: str
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "payload": dict(self.payload),
        }
