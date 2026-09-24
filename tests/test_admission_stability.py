"""Repeated evaluation stability and distinguishable deny reasons."""
from __future__ import annotations

from datetime import timedelta

from admission.models import Caller, Decision, PolicyRule


def _publish_signed_image_policy(services):
    services["policy"].create_version(
        Caller(id="admin", roles=("policy_admin", "key_admin")),
        [PolicyRule(id="images", action=Decision.PASS,
                    match_types=("container-image",),
                    require_signature=True, roles_allowed=("deployer",))],
        request_id="policy-v1", expected_version=0,
    )


def test_three_deny_reasons_are_distinct(services):
    admission = services["admission"]
    admin = Caller(id="admin", roles=("policy_admin", "key_admin"))
    ci = Caller(id="ci", roles=("signer", "deployer"), key_grants=("k1",))
    viewer = Caller(id="viewer", roles=("viewer",))

    # No policy yet -> not covered (manual review), not deny.
    r = admission.evaluate(ci, artifact_digest="sha256:1",
                           artifact_type="container-image", request_id="e0")
    assert r["decision"] == "manual_review"
    assert r["reason"] == "policy_not_covered"

    _publish_signed_image_policy(services)

    # 1) identity insufficient
    denied_identity = admission.evaluate(
        None, artifact_digest="sha256:1",
        artifact_type="container-image", request_id="e1")
    assert denied_identity["reason"] == "identity_unknown"

    # 2) permission insufficient (distinct from not-covered / explicit deny)
    denied_perm = admission.evaluate(
        viewer, artifact_digest="sha256:1",
        artifact_type="container-image", request_id="e2")
    assert denied_perm["decision"] == "deny"
    assert denied_perm["reason"] == "permission_denied"

    # 3) not covered even for a privileged caller (uncovered type)
    uncovered = admission.evaluate(
        ci, artifact_digest="sha256:1", artifact_type="sarif-report",
        request_id="e3")
    assert uncovered["decision"] == "manual_review"
    assert uncovered["reason"] == "policy_not_covered"

    # 4) explicit deny after policy flip (distinct reason code)
    services["policy"].create_version(
        admin,
        [PolicyRule(id="images", action=Decision.DENY,
                    match_types=("container-image",),
                    require_signature=False, roles_allowed=("deployer",))],
        request_id="policy-v2")
    explicit = admission.evaluate(
        ci, artifact_digest="sha256:1",
        artifact_type="container-image", request_id="e4")
    assert explicit["decision"] == "deny"
    assert explicit["reason"] == "policy_explicit_deny"

    reasons = {denied_identity["reason"], denied_perm["reason"],
               uncovered["reason"], explicit["reason"]}
    assert reasons == {
        "identity_unknown", "permission_denied",
        "policy_not_covered", "policy_explicit_deny",
    }


def test_repeated_evaluation_is_stable_under_same_policy_version(services):
    admission = services["admission"]
    keys = services["keys"]
    clock = services["clock"]
    admin = Caller(id="admin", roles=("policy_admin", "key_admin"))
    ci = Caller(id="ci", roles=("signer", "deployer"), key_grants=("k1",))

    keys.generate(admin, key_id="k1", ttl=None)
    keys.grant_signer(admin, "k1", "ci")
    _publish_signed_image_policy(services)
    services["signing"].sign_artifact(
        ci, artifact_digest="sha256:abc", artifact_type="container-image",
        key_id="k1", request_id="sign-1", signature_ttl=timedelta(days=5))

    first = admission.evaluate(
        ci, artifact_digest="sha256:abc", artifact_type="container-image",
        request_id="eval-1")
    assert first["decision"] == "pass" and first["reason"] == "ok"

    # Time passes; the same logical evaluation (same request_id) must remain
    # byte-stable even though the signature expires, because the conclusion was
    # reached under policy v1 at a recorded instant.
    clock.advance(timedelta(days=30))
    second = admission.evaluate(
        ci, artifact_digest="sha256:abc", artifact_type="container-image",
        request_id="eval-1")
    third = admission.evaluate(
        ci, artifact_digest="sha256:abc", artifact_type="container-image",
        request_id="eval-1")
    first_core = {k: v for k, v in first.items() if k != "dedup"}
    for k, v in first_core.items():
        assert second[k] == v
        assert third[k] == v
    assert first["dedup"] is False and second["dedup"] is True

    # A *new* evaluation under the same policy version but current facts can
    # differ (expired) - stability promise is per request/version, not forever.
    fresh = admission.evaluate(
        ci, artifact_digest="sha256:abc", artifact_type="container-image",
        request_id="eval-2")
    assert fresh["reason"] == "signature_expired"

    # Historical replay must reproduce the original pass.
    replay = admission.replay("eval-1")
    assert replay["result"] == first_core
    assert replay["recorded_at"] == first["evaluated_at"]


def test_result_carries_explainable_basis_and_input_summary(services, caplog):
    admission = services["admission"]
    _publish_signed_image_policy(services)
    import logging

    with caplog.at_level(logging.INFO, logger="admission.engine"):
        r = admission.evaluate(
            Caller(id="ci", roles=("deployer",)),
            artifact_digest="sha256:xyz", artifact_type="container-image",
            request_id="eval-log")
    assert r["decision"] == "deny" and r["reason"] == "signature_missing"
    # Explainability: ordered gate trace + rationale + pinned version.
    assert any("gate1" in b for b in r["basis"])
    assert any("gate2" in b and "images" in b for b in r["basis"])
    assert any("gate4" in b for b in r["basis"])
    assert "requires a valid signature" in r["rationale"]
    assert r["policy_version"] == 1 and r["rule_id"] == "images"
    # Log line prints input summary and decision.
    joined = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "eval-log" in joined and "decision=deny" in joined
    assert "signature_status=missing" in joined
