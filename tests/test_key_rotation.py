"""Key rotation vs. registered signatures (multi-signature quorum model).

Business coverage:
* rotating a key immediately stops its historical signatures from counting
  towards the admission threshold, with per-signature reasons in the verdict;
* an artifact whose signatures all belong to rotated keys is never admitted;
* re-signing with the rotation's currently-active successor key restores the
  quorum; duplicate/retry/concurrent re-submissions still count once;
* old-key signatures stay queryable as history and never conflict with the
  replacement signatures;
* conclusions recorded before the rotation replay verbatim afterwards.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from admission.clock import FixedClock
from admission.engine import AdmissionService
from admission.keys import KeyService
from admission.models import Caller, Decision, PolicyRule
from admission.policy import PolicyService
from admission.signing import SigningService
from admission.storage import Store

ADMIN = Caller(id="admin", roles=("key_admin", "policy_admin"))
DIGEST = "sha256:rot1"
TYPE = "container-image"


def _signer(services, signer_id: str, key_id: str) -> Caller:
    keys: KeyService = services["keys"]
    if key_id not in services["store"].state["keys"]:
        keys.generate(ADMIN, key_id=key_id, ttl=None)
    keys.grant_signer(ADMIN, key_id, signer_id)
    return Caller(id=signer_id, roles=("signer", "deployer"), key_grants=(key_id,))


def _quorum_policy(services, min_signatures: int, request_id: str = "p-quorum"):
    services["policy"].create_version(
        ADMIN,
        [PolicyRule(id="images", action=Decision.PASS,
                    match_types=(TYPE,), min_signatures=min_signatures,
                    roles_allowed=("deployer",))],
        request_id=request_id, expected_version=0)


def _evaluate(services, request_id: str) -> dict:
    return services["admission"].evaluate(
        Caller(id="releaser", roles=("deployer",)),
        artifact_digest=DIGEST, artifact_type=TYPE, request_id=request_id)


def _sign(services, caller, key_id, request_id, digest=DIGEST):
    return services["signing"].sign_artifact(
        caller, artifact_digest=digest, artifact_type=TYPE,
        key_id=key_id, request_id=request_id, signature_ttl=None)


def test_rotation_stops_old_signatures_counting_with_explainable_verdict(services):
    """Rotation -> old-key signatures drop out of the count; the verdict shows
    required/counted/missing plus why each rejected signature does not count."""
    _quorum_policy(services, 2)
    alice = _signer(services, "alice", "k-alice")
    bob = _signer(services, "bob", "k-bob")
    _sign(services, alice, "k-alice", "s-alice")
    _sign(services, bob, "k-bob", "s-bob")
    assert _evaluate(services, "e-before")["decision"] == "pass"

    services["keys"].rotate(ADMIN, "k-alice")
    r = _evaluate(services, "e-after-rotate")
    assert r["decision"] == "deny"
    assert r["reason"] == "signature_quorum_not_met"
    quorum = r["signature_quorum"]
    assert quorum["required"] == 2
    assert quorum["counted"] == 1
    assert quorum["missing"] == 1
    assert quorum["counted_signers"] == ["bob"]
    rejected = {(x["signed_by"], x["key_id"], x["status"], x["reason"])
                for x in quorum["rejected"]}
    assert rejected == {("alice", "k-alice", "rotated", "signature_key_rotated")}
    # The explainable basis also narrates the shortfall.
    basis = "\n".join(r["basis"])
    assert "required=2" in basis and "counted=1" in basis
    assert "alice#k-alice -> rotated" in basis


def test_artifact_with_only_rotated_key_signatures_cannot_pass(services):
    """Every registered signature belongs to rotated keys -> never admitted,
    even though signatures are physically present."""
    _quorum_policy(services, 2)
    alice = _signer(services, "alice", "k-alice")
    bob = _signer(services, "bob", "k-bob")
    _sign(services, alice, "k-alice", "s-alice")
    _sign(services, bob, "k-bob", "s-bob")
    assert _evaluate(services, "e-before")["decision"] == "pass"

    services["keys"].rotate(ADMIN, "k-alice")
    services["keys"].rotate(ADMIN, "k-bob")
    r = _evaluate(services, "e-all-rotated")
    assert r["decision"] == "deny"
    assert r["reason"] == "signature_quorum_not_met"
    quorum = r["signature_quorum"]
    assert quorum["counted"] == 0 and quorum["missing"] == 2
    assert {x["status"] for x in quorum["rejected"]} == {"rotated"}
    # Both historical signatures remain registered and queryable.
    listed = services["signing"].get_signatures(DIGEST)["signatures"]
    assert len(listed) == 2


def test_legacy_single_signature_policy_reports_rotation(services):
    """Old 'require a signature' rules keep their semantics: a rotated key's
    signature denies with the specific signature_key_rotated reason, and a
    fresh signature from the successor key satisfies the rule again."""
    services["policy"].create_version(
        ADMIN,
        [PolicyRule(id="images", action=Decision.PASS,
                    match_types=(TYPE,), require_signature=True,
                    roles_allowed=("deployer",))],
        request_id="p-legacy", expected_version=0)
    alice = _signer(services, "alice", "k-alice")
    _sign(services, alice, "k-alice", "s-alice")
    assert _evaluate(services, "e-legacy-ok")["decision"] == "pass"

    rotated = services["keys"].rotate(ADMIN, "k-alice")
    r = _evaluate(services, "e-legacy-rotated")
    assert r["decision"] == "deny"
    assert r["reason"] == "signature_key_rotated"
    assert r["signature_status"] == "rotated"

    new_key = rotated["active_key"]["key_id"]
    alice_new = _signer(services, "alice", new_key)
    _sign(services, alice_new, new_key, "s-alice-new")
    r2 = _evaluate(services, "e-legacy-resigned")
    assert r2["decision"] == "pass"
    assert r2["signature_quorum"]["required"] == 1
    assert r2["signature_quorum"]["counted"] == 1


def test_resign_after_rotation_dedups_retries_and_restores_exact_quorum(services):
    """Re-signing with the successor key: same-signer retries/duplicates with
    that key count once; the quorum is met exactly, not over-counted."""
    _quorum_policy(services, 2)
    alice = _signer(services, "alice", "k-alice")
    bob = _signer(services, "bob", "k-bob")
    _sign(services, alice, "k-alice", "s-alice")
    _sign(services, bob, "k-bob", "s-bob")
    rotated = services["keys"].rotate(ADMIN, "k-alice")
    new_key = rotated["active_key"]["key_id"]
    assert _evaluate(services, "e-rotated")["signature_quorum"]["counted"] == 1

    alice_new = _signer(services, "alice", new_key)
    first = _sign(services, alice_new, new_key, "s-alice-new")
    # Retry with the same request_id and duplicate under a new request_id:
    # both return the original record, no extra slot is created.
    retry = _sign(services, alice_new, new_key, "s-alice-new")
    dup = _sign(services, alice_new, new_key, "s-alice-new-2")
    assert retry["dedup"] is True and dup["dedup"] is True
    assert retry["signature"] == first["signature"] == dup["signature"]

    slots = services["store"].state["signatures"][DIGEST]
    # alice#k-alice (history), bob#k-bob, alice#<new_key>: exactly 3 slots.
    assert len(slots) == 3

    r = _evaluate(services, "e-restored")
    assert r["decision"] == "pass"
    quorum = r["signature_quorum"]
    assert quorum["required"] == 2 and quorum["counted"] == 2
    assert quorum["missing"] == 0
    assert sorted(quorum["counted_signers"]) == ["alice", "bob"]
    # The old-key signature is still visible, still rejected as rotated, and
    # does not collide with alice's new-key signature.
    rotated_entries = [x for x in quorum["rejected"] if x["status"] == "rotated"]
    assert len(rotated_entries) == 1
    assert rotated_entries[0]["key_id"] == "k-alice"

    listed = services["signing"].get_signatures(DIGEST)["signatures"]
    assert len(listed) == 3
    assert {s["key_id"] for s in listed} == {"k-alice", "k-bob", new_key}


def test_one_short_after_rotation_until_second_signer_resigns(services):
    """Threshold 2, both keys rotated: re-signing only one side leaves the
    quorum exactly one short; the second re-sign meets it exactly."""
    _quorum_policy(services, 2)
    alice = _signer(services, "alice", "k-alice")
    bob = _signer(services, "bob", "k-bob")
    _sign(services, alice, "k-alice", "s-alice")
    _sign(services, bob, "k-bob", "s-bob")
    new_alice = services["keys"].rotate(ADMIN, "k-alice")["active_key"]["key_id"]
    new_bob = services["keys"].rotate(ADMIN, "k-bob")["active_key"]["key_id"]

    r0 = _evaluate(services, "e-none-valid")
    assert r0["decision"] == "deny"
    assert r0["signature_quorum"]["counted"] == 0
    assert r0["signature_quorum"]["missing"] == 2

    _sign(services, _signer(services, "alice", new_alice), new_alice, "s-a2")
    r1 = _evaluate(services, "e-one-short")
    assert r1["decision"] == "deny"
    assert r1["reason"] == "signature_quorum_not_met"
    assert r1["signature_quorum"]["counted"] == 1
    assert r1["signature_quorum"]["missing"] == 1

    _sign(services, _signer(services, "bob", new_bob), new_bob, "s-b2")
    r2 = _evaluate(services, "e-exact")
    assert r2["decision"] == "pass"
    assert r2["signature_quorum"]["counted"] == 2
    assert r2["signature_quorum"]["missing"] == 0


def test_recorded_conclusions_replay_verbatim_across_rotation(services):
    """A conclusion recorded before the rotation replays byte-identical after
    the facts changed; the post-rotation conclusion is a new, consistent one."""
    _quorum_policy(services, 2)
    alice = _signer(services, "alice", "k-alice")
    bob = _signer(services, "bob", "k-bob")
    _sign(services, alice, "k-alice", "s-alice")
    _sign(services, bob, "k-bob", "s-bob")
    before = _evaluate(services, "e-before")
    assert before["decision"] == "pass"

    services["keys"].rotate(ADMIN, "k-alice")
    after = _evaluate(services, "e-after")
    assert after["decision"] == "deny"

    admission = services["admission"]
    replay_before = admission.replay("e-before")
    assert replay_before["result"]["decision"] == "pass"
    assert replay_before["result"]["signature_quorum"]["counted"] == 2
    # Replaying again later (even after re-signing) stays identical.
    new_key = next(k for k in services["keys"].list_keys()
                   if k["key_id"].startswith("k-alice-r"))
    alice_new = _signer(services, "alice", new_key["key_id"])
    _sign(services, alice_new, new_key["key_id"], "s-alice-new")
    assert _evaluate(services, "e-restored")["decision"] == "pass"
    replay_before2 = admission.replay("e-before")
    assert replay_before2["result"] == replay_before["result"]
    replay_after = admission.replay("e-after")
    assert replay_after["result"]["decision"] == "deny"
    assert replay_after["result"]["signature_quorum"]["counted"] == 1


def test_concurrent_resign_with_successor_key_counts_once(tmp_path):
    """After rotation, many concurrent/retried re-sign submissions with the
    successor key still produce exactly one slot and one counted seat."""
    data_dir = str(tmp_path / "data")
    n_signers = 4

    def fresh():
        store = Store(data_dir)
        clock = FixedClock()
        keys = KeyService(store, clock)
        return store, SigningService(store, clock, keys)

    store, _ = fresh()
    keys = KeyService(store, FixedClock())
    PolicyService(store, FixedClock()).create_version(
        ADMIN,
        [PolicyRule(id="images", action=Decision.PASS,
                    match_types=(TYPE,), min_signatures=n_signers,
                    roles_allowed=("deployer",))],
        request_id="p1", expected_version=0)
    old_keys, new_keys = [], []
    for i in range(n_signers):
        keys.generate(ADMIN, key_id=f"k{i}", ttl=None)
        keys.grant_signer(ADMIN, f"k{i}", f"signer-{i}")
        old_keys.append(f"k{i}")

    # Everyone signs with the original keys, then every key is rotated.
    for i in range(n_signers):
        _, signing = fresh()
        caller = Caller(id=f"signer-{i}", roles=("signer",), key_grants=(f"k{i}",))
        signing.sign_artifact(caller, artifact_digest=DIGEST, artifact_type=TYPE,
                              key_id=f"k{i}", request_id=f"old-{i}",
                              signature_ttl=None)
    for i in range(n_signers):
        new_id = keys.rotate(ADMIN, f"k{i}")["active_key"]["key_id"]
        keys.grant_signer(ADMIN, new_id, f"signer-{i}")
        new_keys.append(new_id)

    # Mid-rotation evaluation: nothing counts any more.
    store_mid, signing_mid = fresh()
    adm_mid = AdmissionService(store_mid, FixedClock(), signing_mid,
                               PolicyService(store_mid, FixedClock()))
    r_mid = adm_mid.evaluate(Caller(id="releaser", roles=("deployer",)),
                             artifact_digest=DIGEST, artifact_type=TYPE,
                             request_id="e-mid")
    assert r_mid["decision"] == "deny"
    assert r_mid["signature_quorum"]["counted"] == 0

    # All signers re-sign with their successor keys concurrently, each
    # submitting twice (retry) -> exactly one slot per signer.
    def worker(i):
        _, signing = fresh()
        caller = Caller(id=f"signer-{i}", roles=("signer",),
                        key_grants=(new_keys[i],))
        return [signing.sign_artifact(
            caller, artifact_digest=DIGEST, artifact_type=TYPE,
            key_id=new_keys[i], request_id=f"new-{i}-{attempt}",
            signature_ttl=None) for attempt in (0, 1)]

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(n_signers)))

    store_after, signing_after = fresh()
    slots = store_after.state["signatures"][DIGEST]
    # n old (rotated, kept as history) + n new = 2n slots, no duplicates.
    assert len(slots) == 2 * n_signers
    for first, second in results:
        assert first["signature"] == second["signature"]
        assert second["dedup"] is True

    adm = AdmissionService(store_after, FixedClock(), signing_after,
                           PolicyService(store_after, FixedClock()))
    r = adm.evaluate(Caller(id="releaser", roles=("deployer",)),
                     artifact_digest=DIGEST, artifact_type=TYPE,
                     request_id="e-restored")
    assert r["decision"] == "pass"
    quorum = r["signature_quorum"]
    assert quorum["counted"] == n_signers
    assert quorum["missing"] == 0
    assert len(quorum["rejected"]) == n_signers  # the rotated history
    assert {x["status"] for x in quorum["rejected"]} == {"rotated"}


def test_rotation_verdict_log_shows_quorum_and_rejected(services, caplog):
    """The evaluation log line makes the rotation impact observable."""
    _quorum_policy(services, 2)
    alice = _signer(services, "alice", "k-alice")
    bob = _signer(services, "bob", "k-bob")
    _sign(services, alice, "k-alice", "s-alice")
    _sign(services, bob, "k-bob", "s-bob")
    services["keys"].rotate(ADMIN, "k-alice")

    with caplog.at_level(logging.INFO, logger="admission.engine"):
        r = _evaluate(services, "e-logged")
    assert r["reason"] == "signature_quorum_not_met"
    joined = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "quorum=1/2" in joined
    assert "decision=deny" in joined
