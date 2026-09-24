"""Local key generation, HMAC signing/verification and canonical payloads.

Keys are random hex secrets kept in the local state file. This simulates a KMS:
nothing here is suitable for production, but the verify path uses constant-time
comparison and the payload is canonical, so signatures are tamper-evident.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets


def generate_secret(num_bytes: int = 32) -> str:
    return secrets.token_hex(num_bytes)


def canonical_payload(artifact_digest: str, artifact_type: str) -> bytes:
    """Single canonical byte string signed for an artifact.

    Version-prefixed so a future payload change cannot be confused with this one.
    """
    return f"admission-signature/v1\n{artifact_type}\n{artifact_digest}".encode()


def sign(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify(secret: str, payload: bytes, signature: str) -> bool:
    expected = sign(secret, payload)
    return hmac.compare_digest(expected, signature or "")
