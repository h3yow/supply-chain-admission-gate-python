"""Admission semantics: allow / deny / review and distinct denial reasons."""

from gate.models import Artifact, Caller, Decision, DenyReason


def test_signed_image_allowed_for_deployer(service, signed_image, deployer):
    result = service.evaluate(signed_image, deployer)

    assert result.decision is Decision.ALLOW
    assert result.reason is None
    assert result.matched_rule == "signed-images-need-deployer"
    assert result.policy_version == 1
    assert result.signature_fingerprint is not None


def test_unauthorized_caller_distinguished(service, signed_image, guest):
    result = service.evaluate(signed_image, guest)

    assert result.decision is Decision.DENY
    assert result.reason == DenyReason.UNAUTHORIZED_CALLER.value
    assert "deployer" in result.rationale


def test_policy_denied_distinguished(service, deployer):
    bad_lib = Artifact(
        digest="sha256:lib-bad", name="evil", kind="library",
        properties={"trusted": False},
    )
    result = service.evaluate(bad_lib, deployer)

    assert result.decision is Decision.DENY
    assert result.reason == DenyReason.POLICY_DENIED.value


def test_policy_not_covered_distinguished(service, deployer):
    unknown = Artifact(digest="sha256:mystery", name="x", kind="firmware")
    result = service.evaluate(unknown, deployer)

    assert result.decision is Decision.MANUAL_REVIEW
    assert result.reason == DenyReason.POLICY_NOT_COVERED.value


def test_review_rule(service, deployer):
    cfg = Artifact(digest="sha256:cfg", name="app.yaml", kind="config")
    result = service.evaluate(cfg, deployer)

    assert result.decision is Decision.MANUAL_REVIEW
    assert result.matched_rule == "review-config"


def test_repeated_evaluation_is_stable(service, signed_image, deployer):
    first = service.evaluate(signed_image, deployer)
    second = service.evaluate(signed_image, deployer)

    assert first == second
    assert first.evaluation_id == second.evaluation_id
    assert first.decision == second.decision


def test_evaluation_id_is_input_bound(service, signed_image, deployer):
    other_caller = Caller("deployer-2", frozenset({"deployer"}))
    r1 = service.evaluate(signed_image, deployer)
    r2 = service.evaluate(signed_image, other_caller)
    assert r1.evaluation_id != r2.evaluation_id
