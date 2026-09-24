"""String constants for audit event types (shared by storage/replay layers)."""
from __future__ import annotations

POLICY_CREATED = "policy_created"
POLICY_ROLLED_BACK = "policy_rolled_back"
KEY_GENERATED = "key_generated"
KEY_ROTATED = "key_rotated"
KEY_REVOKED = "key_revoked"
SIGNATURE_REGISTERED = "signature_registered"
SIGNATURE_DEDUP_HIT = "signature_dedup_hit"
ADMISSION_EVALUATED = "admission_evaluated"
EVALUATION_REPLAYED = "evaluation_replayed"

KEY_GRANTED = "key_granted"
KEY_GRANT_REVOKED = "key_grant_revoked"
