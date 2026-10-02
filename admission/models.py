"""Domain types, result/error codes and serialization helpers.

This module contains only data definitions; no I/O and no business logic.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    PASS = "pass"
    DENY = "deny"
    MANUAL_REVIEW = "manual_review"


class DenyReason(StrEnum):
    # Identity / permission problems
    IDENTITY_UNKNOWN = "identity_unknown"
    PERMISSION_DENIED = "permission_denied"
    # Policy coverage
    POLICY_NOT_COVERED = "policy_not_covered"
    # Explicit policy verdict
    POLICY_EXPLICIT_DENY = "policy_explicit_deny"
    # Signature problems
    SIGNATURE_MISSING = "signature_missing"
    SIGNATURE_INVALID = "signature_invalid"
    SIGNATURE_EXPIRED = "signature_expired"
    SIGNATURE_KEY_ROTATED = "signature_key_rotated"
    SIGNATURE_KEY_REVOKED = "signature_key_revoked"
    SIGNATURE_UNAUTHORIZED_CALLER = "signature_unauthorized_caller"
    # At least one signature exists but the distinct-signer quorum is not met
    SIGNATURE_QUORUM_NOT_MET = "signature_quorum_not_met"


class ErrorCode(StrEnum):
    CALLER_REQUIRED = "caller_required"
    PERMISSION_DENIED = "permission_denied"
    KEY_NOT_FOUND = "key_not_found"
    KEY_REVOKED = "key_revoked"
    KEY_ROTATED = "key_rotated"
    KEY_EXISTS = "key_exists"
    SIGNATURE_NOT_FOUND = "signature_not_found"
    POLICY_NOT_FOUND = "policy_not_found"
    POLICY_VERSION_CONFLICT = "policy_version_conflict"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    NOTHING_TO_REPLAY = "nothing_to_replay"
    INVALID_PAYLOAD = "invalid_payload"


class AdmissionError(Exception):
    """Base class for errors that map to a stable, distinguishable HTTP code."""

    error_code: ErrorCode = ErrorCode.INVALID_PAYLOAD
    http_status: int = 400

    def __init__(self, message: str, *, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": self.error_code.value,
            "message": self.message,
            "details": self.details,
        }


class CallerRequiredError(AdmissionError):
    error_code = ErrorCode.CALLER_REQUIRED
    http_status = 401


class KeyNotFoundError(AdmissionError):
    error_code = ErrorCode.KEY_NOT_FOUND
    http_status = 404


class KeyRevokedError(AdmissionError):
    error_code = ErrorCode.KEY_REVOKED
    http_status = 409


class KeyRotatedError(AdmissionError):
    error_code = ErrorCode.KEY_ROTATED
    http_status = 409


class KeyExistsError(AdmissionError):
    error_code = ErrorCode.KEY_EXISTS
    http_status = 409


class SignatureNotFoundError(AdmissionError):
    error_code = ErrorCode.SIGNATURE_NOT_FOUND
    http_status = 404


class PolicyNotFoundError(AdmissionError):
    error_code = ErrorCode.POLICY_NOT_FOUND
    http_status = 404


class PolicyVersionConflictError(AdmissionError):
    error_code = ErrorCode.POLICY_VERSION_CONFLICT
    http_status = 409


class IdempotencyConflictError(AdmissionError):
    error_code = ErrorCode.IDEMPOTENCY_CONFLICT
    http_status = 409


class NothingToReplayError(AdmissionError):
    error_code = ErrorCode.NOTHING_TO_REPLAY
    http_status = 404


@dataclass(frozen=True)
class Caller:
    """Authenticated caller identity (simulated by request headers)."""

    id: str
    roles: tuple[str, ...] = ()
    key_grants: tuple[str, ...] = ()

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_role_any(self, roles) -> bool:
        return any(r in self.roles for r in roles)

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "roles": list(self.roles), "key_grants": list(self.key_grants)}


@dataclass(frozen=True)
class ArtifactManifest:
    """Artifacts are identified by an immutable content digest + type."""

    digest: str
    artifact_type: str
    size: int = 0

    def summary(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "artifact_type": self.artifact_type,
            "size": self.size,
        }


@dataclass(frozen=True)
class PolicyRule:
    """One rule inside a policy version.

    match_types selects artifact types (empty tuple = all types).
    require_signature makes a missing/invalid signature a deny.
    min_signatures is the quorum of *distinct* signing parties whose
    signatures must all be currently valid; it only applies when
    require_signature is set. The default of 1 reproduces the original
    "at least one valid signature" semantics exactly.
    """

    id: str
    action: Decision
    match_types: tuple[str, ...] = ()
    require_signature: bool = False
    roles_allowed: tuple[str, ...] = ()  # empty tuple = any authenticated caller
    min_signatures: int = 1

    def matches(self, artifact_type: str) -> bool:
        return not self.match_types or artifact_type in self.match_types


@dataclass(frozen=True)
class PolicyVersion:
    version: int
    rules: tuple[PolicyRule, ...]
    created_at: str
    created_by: str
    comment: str = ""

    def summary(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "rule_ids": [r.id for r in self.rules],
            "created_at": self.created_at,
            "created_by": self.created_by,
            "comment": self.comment,
        }


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    secret: str  # local-only simulated key material
    created_at: str
    created_by: str
    expires_at: str | None = None
    rotated_at: str | None = None
    rotated_to: str | None = None
    revoked_at: str | None = None
    revoked_reason: str | None = None

    @property
    def is_active(self) -> bool:
        return self.rotated_at is None and self.revoked_at is None

    def summary(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "expires_at": self.expires_at,
            "rotated_at": self.rotated_at,
            "rotated_to": self.rotated_to,
            "revoked_at": self.revoked_at,
            "revoked_reason": self.revoked_reason,
            "status": "active" if self.is_active else (
                "revoked" if self.revoked_at else "rotated"
            ),
        }


@dataclass(frozen=True)
class SignatureRecord:
    artifact_digest: str
    key_id: str
    signature: str
    signed_at: str
    signed_by: str
    expires_at: str | None

    def summary(self) -> dict[str, Any]:
        return {
            "artifact_digest": self.artifact_digest,
            "key_id": self.key_id,
            "signature": self.signature,
            "signed_at": self.signed_at,
            "signed_by": self.signed_by,
            "expires_at": self.expires_at,
        }


class AuditEventType(StrEnum):
    POLICY_CREATED = "policy_created"
    POLICY_ROLLED_BACK = "policy_rolled_back"
    KEY_GENERATED = "key_generated"
    KEY_ROTATED = "key_rotated"
    KEY_REVOKED = "key_revoked"
    SIGNATURE_REGISTERED = "signature_registered"
    SIGNATURE_DEDUP_HIT = "signature_dedup_hit"
    ADMISSION_EVALUATED = "admission_evaluated"
    EVALUATION_REPLAYED = "evaluation_replayed"


@dataclass(frozen=True)
class AuditEvent:
    seq: int
    event_type: AuditEventType
    occurred_at: str
    actor: str
    request_id: str
    payload: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "event_type": self.event_type.value,
            "occurred_at": self.occurred_at,
            "actor": self.actor,
            "request_id": self.request_id,
            "payload": self.payload,
        }


@dataclass(frozen=True)
class EvaluationResult:
    decision: Decision
    reason: str  # "ok" or a DenyReason value
    policy_version: int
    rule_id: str | None
    evaluated_at: str
    request_id: str
    caller: dict[str, Any]
    artifact: dict[str, Any]
    signature: dict[str, Any] | None
    signature_status: str | None
    rationale: str
    basis: list[str]
    # Multi-signature quorum detail: required/counted/missing plus the
    # per-signature verdicts. None when the matched rule does not require
    # signatures at all.
    signature_report: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "rule_id": self.rule_id,
            "evaluated_at": self.evaluated_at,
            "request_id": self.request_id,
            "caller": self.caller,
            "artifact": self.artifact,
            "signature": self.signature,
            "signature_status": self.signature_status,
            "signature_report": self.signature_report,
            "rationale": self.rationale,
            "basis": self.basis,
        }


def to_plain(obj: Any) -> Any:
    """Convert dataclasses/enums nested in dicts/lists to JSON-ready values."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_plain(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, StrEnum):
        return obj.value
    if isinstance(obj, dict):
        return {k: to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_plain(v) for v in obj]
    return obj
