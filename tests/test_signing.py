"""Key rotation, signature expiry, revocation and authorized signing."""

from gate.errors import (
    KeyRevokedError,
    SignatureExpiredError,
    SignatureInvalidError,
    UnauthorizedCallerError,
)
from gate.models import Artifact, Caller, Decision, DenyReason

SIGNER = Caller("signer-1", frozenset({"signer"}))


def test_unsigned_image_denied_with_signature_reason(service, image, deployer):
    result = service.evaluate(image, deployer)

    assert result.decision is Decision.DENY
    assert result.reason == DenyReason.SIGNATURE_INVALID.value


def test_non_signer_cannot_sign(service, image):
    impostor = Caller("mallory", frozenset({"deployer"}))

    try:
        service.submit_signature(image, impostor)
    except UnauthorizedCallerError:
        pass
    else:
        raise AssertionError("non-signer should be rejected")

    assert service.signing.get_record(image.digest) is None
    rejected = service.audit_events("signature.rejected")
    assert len(rejected) == 1
    assert rejected[0]["payload"]["reason"] == "unauthorized_caller"


def test_expired_signature_fails(service, clock, image, deployer):
    service.submit_signature(image, SIGNER)

    clock.advance(101)  # signature ttl is 100s
    result = service.evaluate(image, deployer)

    assert result.decision is Decision.DENY
    assert result.reason == DenyReason.SIGNATURE_EXPIRED.value

    try:
        service.signing.verify(image)
    except SignatureExpiredError:
        pass
    else:
        raise AssertionError("expired signature must not verify")


def test_signature_before_rotation_fails_after_rotation(service, image, deployer):
    service.submit_signature(image, SIGNER)
    old_fingerprint = service.signing.get_record(image.digest).fingerprint()

    new_key = service.rotate_key()
    result = service.evaluate(image, deployer)

    assert result.decision is Decision.DENY
    assert result.reason == DenyReason.SIGNATURE_INVALID.value
    assert "rotated-out" in result.rationale
    # old record is retained for traceability, not deleted
    record = service.signing.get_record(image.digest)
    assert record is not None
    assert record.fingerprint() == old_fingerprint
    assert record.key_id != new_key


def test_revoked_key_fails(service, image, deployer):
    service.submit_signature(image, SIGNER)
    record = service.signing.get_record(image.digest)

    service.revoke_key(record.key_id)
    result = service.evaluate(image, deployer)

    assert result.decision is Decision.DENY
    assert result.reason == DenyReason.KEY_REVOKED.value
    try:
        service.signing.verify(image)
    except KeyRevokedError:
        pass
    else:
        raise AssertionError("revoked-key signature must not verify")


def test_resigning_with_new_key_after_rotation_is_impossible_without_reset(
    service, image, deployer
):
    # First rotation: the stale signature remains and blocks verification.
    service.submit_signature(image, SIGNER)
    service.rotate_key()
    try:
        service.submit_signature(image, SIGNER)
    except SignatureInvalidError:
        pass
    else:
        raise AssertionError("stale pre-rotation signature must not be silently replaced")


def test_retry_returns_same_signature(service, image):
    first, created1 = service.submit_signature(image, SIGNER)
    second, created2 = service.submit_signature(image, SIGNER)

    assert created1 is True
    assert created2 is False
    assert first == second
    assert len(service.store.signatures) == 1


def test_tampered_artifact_fails_mac(service, image, deployer):
    service.submit_signature(image, SIGNER)
    tampered = Artifact(digest=image.digest, name="tampered", kind="container-image")

    result = service.evaluate(tampered, deployer)
    assert result.decision is Decision.DENY
    assert result.reason == DenyReason.SIGNATURE_INVALID.value


def test_signature_valid_at_historical_time_after_expiry(service, clock, image, deployer):
    service.submit_signature(image, SIGNER)
    clock.advance(500)
    # replay evaluation pinned to a moment within the signature validity
    historical = service.evaluate(image, deployer, at=1_000_050.0)
    assert historical.decision is Decision.ALLOW
