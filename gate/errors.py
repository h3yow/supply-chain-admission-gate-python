"""Error classification for the admission gate."""

from __future__ import annotations


class GateError(Exception):
    """Base error; ``code`` identifies the classified reason."""

    code = "gate_error"


class UnauthorizedCallerError(GateError):
    code = "unauthorized_caller"


class PolicyNotFoundError(GateError):
    code = "policy_not_covered"


class PolicyDeniedError(GateError):
    code = "policy_denied"


class SignatureInvalidError(GateError):
    code = "signature_invalid"


class SignatureExpiredError(GateError):
    code = "signature_expired"


class KeyRevokedError(GateError):
    code = "key_revoked"


class KeyUnknownError(GateError):
    code = "key_unknown"


class ConcurrencyConflictError(GateError):
    code = "concurrency_conflict"
