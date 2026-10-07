"""Key rotation, signature TTL/expiry, revocation and unauthorized callers."""
from __future__ import annotations

from datetime import timedelta

import pytest

from admission.keys import KeyService
from admission.models import (
    AdmissionError,
    Caller,
    Decision,
    ErrorCode,
    PolicyRule,
)

ADMIN = Caller(id="admin", roles=("key_admin", "policy_admin"))


def test_unauthorized_caller_cannot_register_signature(services):
    keys: KeyService = services["keys"]
    signing = services["signing"]
    keys.generate(ADMIN, key_id="k1", ttl=None)
    keys.grant_signer(ADMIN, "k1", "ci")

    # No signer role at all.
    no_role = Caller(id="x", roles=(), key_grants=("k1",))
    with pytest.raises(AdmissionError) as exc:
        signing.sign_artifact(no_role, artifact_digest="sha256:a",
                              artifact_type="container-image",
                              key_id="k1", request_id="r1")
    assert exc.value.error_code is ErrorCode.PERMISSION_DENIED

    # Signer role + token claim, but no server-side grant.
    evil = Caller(id="evil", roles=("signer",), key_grants=("k1",))
    with pytest.raises(AdmissionError) as exc:
        signing.sign_artifact(evil, artifact_digest="sha256:a",
                              artifact_type="container-image",
                              key_id="k1", request_id="r2")
    assert exc.value.error_code is ErrorCode.PERMISSION_DENIED

    # Token does not even claim the grant.
    ci = Caller(id="ci", roles=("signer",), key_grants=())
    with pytest.raises(AdmissionError) as exc:
        signing.sign_artifact(ci, artifact_digest="sha256:a",
                              artifact_type="container-image",
                              key_id="k1", request_id="r3")
    assert exc.value.error_code is ErrorCode.PERMISSION_DENIED
    assert "sha256:a" not in services["store"].state["signatures"]


def test_expired_signature_is_denied_but_valid_before_ttl(services):
    keys, signing, clock, admission = (services[k] for k in
                                       ("keys", "signing", "clock", "admission"))
    keys.generate(ADMIN, key_id="k1", ttl=None)
    keys.grant_signer(ADMIN, "k1", "ci")
    services["policy"].create_version(
        Caller(id="admin", roles=("policy_admin",)),
        [PolicyRule(
            id="img", action=Decision.PASS,
            match_types=("container-image",), require_signature=True)],
        request_id="p1", expected_version=0)

    ci = Caller(id="ci", roles=("signer", "deployer"), key_grants=("k1",))
    signing.sign_artifact(ci, artifact_digest="sha256:a",
                          artifact_type="container-image", key_id="k1",
                          request_id="s1", signature_ttl=timedelta(days=7))

    assert signing.validate_signature("sha256:a", "container-image")[1] == "valid"
    clock.advance(timedelta(days=7, seconds=1))
    status, reason = signing.validate_signature(
        "sha256:a", "container-image")[1:]
    assert status == "expired" and reason == "signature_expired"

    r = admission.evaluate(ci, artifact_digest="sha256:a",
                           artifact_type="container-image", request_id="e1")
    assert r["decision"] == "deny" and r["reason"] == "signature_expired"
    assert r["signature_status"] == "expired"


def test_rotation_retires_old_key_signatures_retroactively(services):
    """Rotation invalidates *every* signature made with the old key, even
    signatures registered before the rotation happened. The record is kept,
    and re-signing with the active replacement key is valid again."""
    keys, signing = services["keys"], services["signing"]
    keys.generate(ADMIN, key_id="k1", ttl=None)
    keys.grant_signer(ADMIN, "k1", "ci")
    ci = Caller(id="ci", roles=("signer",), key_grants=("k1",))

    # Signed before rotation.
    signing.sign_artifact(ci, artifact_digest="sha256:old",
                          artifact_type="container-image", key_id="k1",
                          request_id="s-old", signature_ttl=None)
    assert signing.validate_signature(
        "sha256:old", "container-image")[1] == "valid"

    rotated = keys.rotate(ADMIN, "k1", comment="scheduled rotation")
    new_id = rotated["active_key"]["key_id"]

    # The pre-rotation signature stops counting the moment the key rotates.
    status, reason = signing.validate_signature(
        "sha256:old", "container-image")[1:]
    assert status == "rotated" and reason == "signature_key_rotated"

    # The record is not deleted: history stays queryable.
    listed = signing.get_signatures("sha256:old")["signatures"]
    assert [s["key_id"] for s in listed] == ["k1"]

    # Signing with the old key after rotation is rejected at registration.
    with pytest.raises(AdmissionError) as exc:
        signing.sign_artifact(ci, artifact_digest="sha256:new",
                              artifact_type="container-image", key_id="k1",
                              request_id="s-new")
    assert exc.value.error_code is ErrorCode.KEY_ROTATED

    # New key works only after grant; artifact signed with it is valid.
    keys.grant_signer(ADMIN, new_id, "ci")
    ci_new = Caller(id="ci", roles=("signer",), key_grants=(new_id,))
    signing.sign_artifact(ci_new, artifact_digest="sha256:new",
                          artifact_type="container-image", key_id=new_id,
                          request_id="s-new2", signature_ttl=None)
    assert signing.validate_signature("sha256:new", "container-image")[1] == "valid"

    # Rotating twice is an explicit error.
    with pytest.raises(AdmissionError) as exc:
        keys.rotate(ADMIN, "k1")
    assert exc.value.error_code is ErrorCode.KEY_ROTATED


def test_revoked_key_invalidates_existing_signatures(services):
    keys, signing = services["keys"], services["signing"]
    keys.generate(ADMIN, key_id="k1", ttl=None)
    keys.grant_signer(ADMIN, "k1", "ci")
    ci = Caller(id="ci", roles=("signer",), key_grants=("k1",))
    signing.sign_artifact(ci, artifact_digest="sha256:a",
                          artifact_type="container-image", key_id="k1",
                          request_id="s1", signature_ttl=None)
    keys.revoke(ADMIN, "k1", reason="suspected compromise")

    status, reason = signing.validate_signature(
        "sha256:a", "container-image")[1:]
    assert status == "revoked" and reason == "signature_key_revoked"

    # Cannot sign with a revoked key.
    with pytest.raises(AdmissionError) as exc:
        signing.sign_artifact(ci, artifact_digest="sha256:b",
                              artifact_type="container-image", key_id="k1",
                              request_id="s2")
    assert exc.value.error_code is ErrorCode.KEY_REVOKED


def test_grant_revocation_retroactively_marks_signature_unauthorized(services):
    keys, signing = services["keys"], services["signing"]
    keys.generate(ADMIN, key_id="k1", ttl=None)
    keys.grant_signer(ADMIN, "k1", "ci")
    ci = Caller(id="ci", roles=("signer",), key_grants=("k1",))
    signing.sign_artifact(ci, artifact_digest="sha256:a",
                          artifact_type="container-image", key_id="k1",
                          request_id="s1", signature_ttl=None)
    assert signing.validate_signature("sha256:a", "container-image")[1] == "valid"

    keys.revoke_signer_grant(ADMIN, "k1", "ci")
    status, reason = signing.validate_signature(
        "sha256:a", "container-image")[1:]
    assert status == "unauthorized_caller"
    assert reason == "signature_unauthorized_caller"

    # Re-grant restores validity without re-signing.
    keys.grant_signer(ADMIN, "k1", "ci")
    assert signing.validate_signature("sha256:a", "container-image")[1] == "valid"


def test_tampered_signature_payload_is_invalid(services):
    keys, signing = services["keys"], services["signing"]
    keys.generate(ADMIN, key_id="k1", ttl=None)
    keys.grant_signer(ADMIN, "k1", "ci")
    ci = Caller(id="ci", roles=("signer",), key_grants=("k1",))
    signing.sign_artifact(ci, artifact_digest="sha256:a",
                          artifact_type="container-image", key_id="k1",
                          request_id="s1", signature_ttl=None)
    # Same digest claimed under a different type changes canonical payload.
    status, reason = signing.validate_signature("sha256:a", "firmware")[1:]
    assert status == "invalid" and reason == "signature_invalid"
