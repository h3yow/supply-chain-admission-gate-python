"""Policy versioning, rollback and historical replay."""

from gate.errors import PolicyNotFoundError
from gate.models import (
    Artifact,
    Caller,
    Decision,
    DenyReason,
    PolicyRule,
    RuleEffect,
)

ADMIN = Caller("admin", frozenset({"admin"}))
DEPLOYER = Caller("deployer-1", frozenset({"deployer"}))


def test_policy_versions_are_append_only(service):
    v2 = service.publish_policy(
        [
            PolicyRule(
                name="allow-everything",
                artifact_kinds=frozenset({"*"}),
                effect=RuleEffect.ALLOW,
            )
        ],
        author="admin",
    )
    assert v2 == 2
    versions = [p.version for p in service.policies.list_versions()]
    assert versions == [1, 2]
    # v1 remains fetchable for replay
    assert service.policies.get(1).note == "demo policy"


def test_replay_old_version_reproduces_historical_decision(service, deployer):
    mystery = Artifact(digest="sha256:mystery", name="x", kind="firmware")

    # under v1: uncovered -> manual review / policy_not_covered
    old = service.evaluate(mystery, deployer, policy_version=1)
    assert old.decision is Decision.MANUAL_REVIEW
    assert old.reason == DenyReason.POLICY_NOT_COVERED.value

    # v2 explicitly allows everything
    service.publish_policy(
        [
            PolicyRule(
                name="allow-everything",
                artifact_kinds=frozenset({"*"}),
                effect=RuleEffect.ALLOW,
            )
        ],
        author="admin",
        note="open up",
    )
    current = service.evaluate(mystery, deployer)
    assert current.decision is Decision.ALLOW

    # replay pinned to v1 must reproduce the old conclusion and id
    replayed = service.evaluate(mystery, deployer, policy_version=1)
    assert replayed == old
    assert replayed.evaluation_id == old.evaluation_id
    assert replayed.policy_version == 1


def test_rollback_publishes_new_version_preserving_history(service, deployer):
    mystery = Artifact(digest="sha256:mystery", name="x", kind="firmware")

    service.publish_policy(
        [
            PolicyRule(
                name="allow-everything",
                artifact_kinds=frozenset({"*"}),
                effect=RuleEffect.ALLOW,
            )
        ],
        author="admin",
    )
    assert service.evaluate(mystery, deployer).decision is Decision.ALLOW

    new_version = service.rollback_policy(1, ADMIN.identity)
    assert new_version == 3

    # current conclusion now matches v1 semantics again
    rolled = service.evaluate(mystery, deployer)
    assert rolled.decision is Decision.MANUAL_REVIEW
    assert rolled.policy_version == 3

    # all three versions remain, and rollback is audited
    versions = [p.version for p in service.policies.list_versions()]
    assert versions == [1, 2, 3]
    rollback_events = service.audit_events("policy.rolled_back")
    assert len(rollback_events) == 1
    assert rollback_events[0]["payload"] == {
        "from_version": 1,
        "new_version": 3,
        "author": "admin",
    }


def test_missing_version_raises_classified_error(service, deployer):
    image = Artifact(digest="sha256:abc", name="app", kind="container-image")
    try:
        service.evaluate(image, deployer, policy_version=99)
    except PolicyNotFoundError as exc:
        assert exc.code == "policy_not_covered"
    else:
        raise AssertionError("missing version should raise PolicyNotFoundError")


def test_audit_trail_is_time_ordered_and_complete(service, signed_image, deployer):
    service.evaluate(signed_image, deployer)
    events = service.audit_events()

    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps)

    eval_events = service.audit_events("admission.evaluated")
    assert eval_events, "evaluation must be audited"
    payload = eval_events[-1]["payload"]
    assert payload["decision"] == "allow"
    assert payload["artifact_summary"]["digest"] == signed_image.digest
    assert payload["caller"]["identity"] == deployer.identity
    assert payload["rationale"], "decision basis must be recorded"
