"""Policy rollback semantics and historical reproducibility."""
from __future__ import annotations

from datetime import timedelta

from admission.clock import parse_ts
from admission.models import Caller, Decision, PolicyRule

ADMIN = Caller(id="admin", roles=("key_admin", "policy_admin"))
CI = Caller(id="ci", roles=("signer", "deployer"), key_grants=("k1",))


def _rule(action: Decision, require_signature: bool = False) -> PolicyRule:
    return PolicyRule(id="images", action=action,
                      match_types=("container-image",),
                      require_signature=require_signature,
                      roles_allowed=("deployer",))


def test_rollback_appends_new_version_and_reproduces_history(services):
    policy = services["policy"]
    admission = services["admission"]
    clock = services["clock"]
    keys = services["keys"]

    keys.generate(ADMIN, key_id="k1", ttl=None)
    keys.grant_signer(ADMIN, "k1", "ci")

    # v1: allow
    policy.create_version(ADMIN, [_rule(Decision.PASS)],
                          request_id="p1", expected_version=0)
    r_v1 = admission.evaluate(
        CI, artifact_digest="sha256:a", artifact_type="container-image",
        request_id="eval-v1")
    assert r_v1["decision"] == "pass"

    # v2: explicit deny
    clock.advance(timedelta(days=1))
    policy.create_version(ADMIN, [_rule(Decision.DENY)], request_id="p2")
    r_v2 = admission.evaluate(
        CI, artifact_digest="sha256:a", artifact_type="container-image",
        request_id="eval-v2")
    assert r_v2["decision"] == "deny"
    assert r_v2["reason"] == "policy_explicit_deny"

    # roll back to v1's rules -> v3 (append-only; v1/v2 stay intact)
    clock.advance(timedelta(days=1))
    v3 = policy.rollback(ADMIN, 1, request_id="rb1")
    assert v3["version"] == 3
    versions = policy.list_versions()
    assert [v["version"] for v in versions] == [1, 2, 3]
    assert all(v["rule_ids"] == ["images"] for v in versions)
    assert policy.get_version(1).rules[0].action is Decision.PASS
    assert policy.get_version(2).rules[0].action is Decision.DENY
    assert policy.current_version().rules[0].action is Decision.PASS

    r_v3 = admission.evaluate(
        CI, artifact_digest="sha256:a", artifact_type="container-image",
        request_id="eval-v3")
    assert r_v3["decision"] == "pass"

    # Historical conclusions are reproducible verbatim at any later time,
    # including the deny made under v2.
    assert admission.replay("eval-v1")["result"]["decision"] == "pass"
    replayed_v2 = admission.replay("eval-v2")["result"]
    assert replayed_v2["decision"] == "deny"
    assert replayed_v2["policy_version"] == 2
    assert admission.replay("eval-v3")["result"]["policy_version"] == 3


def test_pinned_version_isolates_evaluation_from_later_changes(services):
    policy = services["policy"]
    admission = services["admission"]
    clock = services["clock"]
    policy.create_version(ADMIN, [_rule(Decision.PASS)],
                          request_id="p1", expected_version=0)
    clock.advance(timedelta(days=2))
    policy.create_version(ADMIN, [_rule(Decision.DENY)], request_id="p2")
    clock.advance(timedelta(days=2))
    policy.create_version(ADMIN, [_rule(Decision.MANUAL_REVIEW)], request_id="p3")

    # Explicit version pinning lets an auditor replay the rule set that was
    # effective when an event happened.
    pinned_v1 = admission.evaluate(
        CI, artifact_digest="sha256:a", artifact_type="container-image",
        request_id="pin1", policy_version=1)
    pinned_v2 = admission.evaluate(
        CI, artifact_digest="sha256:a", artifact_type="container-image",
        request_id="pin2", policy_version=2)
    current = admission.evaluate(
        CI, artifact_digest="sha256:a", artifact_type="container-image",
        request_id="pin3")
    assert pinned_v1["decision"] == "pass"
    assert pinned_v2["decision"] == "deny"
    assert current["decision"] == "manual_review"
    assert pinned_v1["policy_version"] == 1


def test_audit_trail_supports_time_range_walkback(services):
    policy = services["policy"]
    clock = services["clock"]
    audit = services["audit"]

    t0 = clock.now().isoformat(timespec="seconds")
    clock.advance(timedelta(days=1))
    policy.create_version(ADMIN, [_rule(Decision.PASS)], request_id="p1")
    t1 = clock.now().isoformat(timespec="seconds")
    clock.advance(timedelta(days=1))
    policy.create_version(ADMIN, [_rule(Decision.DENY)], request_id="p2")
    t2 = clock.now().isoformat(timespec="seconds")
    clock.advance(timedelta(days=1))
    policy.rollback(ADMIN, 1, request_id="rb1")

    all_events = audit.all_events()
    assert [e["event_type"] for e in all_events] == [
        "policy_created", "policy_created", "policy_rolled_back"]

    # Time-window walkback: a window starting just after v1 and ending at v2
    # sees only the v2 (deny) creation event.
    window = audit.between(
        (parse_ts(t1) + timedelta(seconds=1)).isoformat(timespec="seconds"),
        t2,
    )
    assert len(window) == 1
    assert window[0]["payload"]["policy"]["version"] == 2

    # Strictly before the first change -> nothing.
    assert audit.between(None, t0) == []
    # Rollback event carries source version for traceability.
    rb = audit.by_type("policy_rolled_back")
    assert rb[0]["payload"]["source_version"] == 1
