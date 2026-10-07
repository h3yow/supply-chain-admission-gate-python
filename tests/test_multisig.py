"""Multi-signer quorum: registration dedup, threshold evaluation, re-signing."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from admission.clock import FixedClock
from admission.keys import KeyService
from admission.models import Caller, Decision, PolicyRule
from admission.policy import PolicyService
from admission.signing import SigningService
from admission.storage import Store

ADMIN = Caller(id="admin", roles=("key_admin", "policy_admin"))
DIGEST = "sha256:multi1"
TYPE = "container-image"


def _signer(services, signer_id: str, key_id: str) -> Caller:
    """Create a key (if needed), grant it, and return the signer identity."""
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


def test_quorum_met_exactly_with_distinct_signers(services):
    _quorum_policy(services, 2)
    alice = _signer(services, "alice", "k-alice")
    bob = _signer(services, "bob", "k-bob")
    signing = services["signing"]
    signing.sign_artifact(alice, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-alice", request_id="s-alice",
                          signature_ttl=None)
    signing.sign_artifact(bob, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-bob", request_id="s-bob",
                          signature_ttl=None)

    r = _evaluate(services, "e-pass")
    assert r["decision"] == "pass" and r["reason"] == "ok"
    quorum = r["signature_quorum"]
    assert quorum["required"] == 2 and quorum["counted"] == 2
    assert quorum["missing"] == 0
    assert sorted(quorum["counted_signers"]) == ["alice", "bob"]
    assert quorum["rejected"] == []


def test_quorum_one_short_is_denied_and_distinguishable_from_missing(services):
    _quorum_policy(services, 2)

    # No signatures at all -> signature_missing (not quorum_not_met).
    r0 = _evaluate(services, "e-none")
    assert r0["decision"] == "deny" and r0["reason"] == "signature_missing"
    assert r0["signature_quorum"]["counted"] == 0

    alice = _signer(services, "alice", "k-alice")
    services["signing"].sign_artifact(
        alice, artifact_digest=DIGEST, artifact_type=TYPE,
        key_id="k-alice", request_id="s-alice", signature_ttl=None)

    # Signed, but one short of the threshold -> quorum_not_met.
    r1 = _evaluate(services, "e-short")
    assert r1["decision"] == "deny"
    assert r1["reason"] == "signature_quorum_not_met"
    quorum = r1["signature_quorum"]
    assert quorum["required"] == 2 and quorum["counted"] == 1
    assert quorum["missing"] == 1
    assert "required=2" in "\n".join(r1["basis"])


def test_same_signer_resubmission_never_counts_twice(services):
    _quorum_policy(services, 2)
    alice = _signer(services, "alice", "k-alice")
    signing = services["signing"]
    first = signing.sign_artifact(alice, artifact_digest=DIGEST,
                                  artifact_type=TYPE, key_id="k-alice",
                                  request_id="s1", signature_ttl=None)

    # Retry with the same request_id -> original record, dedup flag.
    retry = signing.sign_artifact(alice, artifact_digest=DIGEST,
                                  artifact_type=TYPE, key_id="k-alice",
                                  request_id="s1", signature_ttl=None)
    assert retry["dedup"] is True
    assert retry["signature"] == first["signature"]

    # Duplicate submission under a *new* request_id -> same record back,
    # still a single registered signature (no idempotency_conflict).
    dup = signing.sign_artifact(alice, artifact_digest=DIGEST,
                                artifact_type=TYPE, key_id="k-alice",
                                request_id="s2", signature_ttl=None)
    assert dup["dedup"] is True
    assert dup["signature"] == first["signature"]
    assert len(services["store"].state["signatures"][DIGEST]) == 1

    # Same signer with a *second* key is registered (history kept) but can
    # never fill a second seat: the signer already counted.
    alice2 = _signer(services, "alice", "k-alice-2")
    signing.sign_artifact(alice2, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-alice-2", request_id="s3",
                          signature_ttl=None)
    assert len(services["store"].state["signatures"][DIGEST]) == 2

    r = _evaluate(services, "e-dup")
    assert r["decision"] == "deny"
    assert r["reason"] == "signature_quorum_not_met"
    quorum = r["signature_quorum"]
    assert quorum["counted"] == 1 and quorum["counted_signers"] == ["alice"]
    dup_entries = [x for x in quorum["rejected"]
                   if x["status"] == "duplicate_signer"]
    assert len(dup_entries) == 1 and dup_entries[0]["key_id"] == "k-alice-2"


def test_same_key_cannot_fill_two_seats(services):
    """Two different signers sharing one key: only the first counts."""
    _quorum_policy(services, 2)
    keys = services["keys"]
    keys.generate(ADMIN, key_id="k-shared", ttl=None)
    keys.grant_signer(ADMIN, "k-shared", "alice")
    keys.grant_signer(ADMIN, "k-shared", "bob")
    alice = Caller(id="alice", roles=("signer",), key_grants=("k-shared",))
    bob = Caller(id="bob", roles=("signer",), key_grants=("k-shared",))
    signing = services["signing"]
    signing.sign_artifact(alice, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-shared", request_id="s-alice",
                          signature_ttl=None)
    signing.sign_artifact(bob, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-shared", request_id="s-bob",
                          signature_ttl=None)

    r = _evaluate(services, "e-shared")
    assert r["decision"] == "deny"
    assert r["reason"] == "signature_quorum_not_met"
    quorum = r["signature_quorum"]
    assert quorum["counted"] == 1
    assert any(x["status"] == "duplicate_key" for x in quorum["rejected"])


def test_rejected_signatures_carry_individual_reasons(services):
    _quorum_policy(services, 2)
    alice = _signer(services, "alice", "k-alice")
    bob = _signer(services, "bob", "k-bob")
    signing = services["signing"]
    signing.sign_artifact(alice, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-alice", request_id="s-alice",
                          signature_ttl=timedelta(days=1))
    signing.sign_artifact(bob, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-bob", request_id="s-bob",
                          signature_ttl=None)
    # Alice's signature expires; Bob's grant is revoked.
    services["clock"].advance(timedelta(days=2))
    keys = services["keys"]
    keys.revoke_signer_grant(ADMIN, "k-bob", "bob")

    r = _evaluate(services, "e-reasons")
    assert r["decision"] == "deny"
    assert r["reason"] == "signature_quorum_not_met"
    rejected = {(x["signed_by"], x["status"]) for x in
                r["signature_quorum"]["rejected"]}
    assert rejected == {("alice", "expired"), ("bob", "unauthorized_caller")}


def test_resign_with_active_key_after_rotation_restores_quorum(services):
    """Key rotation -> every signature made with the old key stops counting
    immediately (even pre-rotation ones) -> the artifact can no longer pass;
    re-sign with the current active key fills the seat again. The old records
    stay queryable, and the conclusion recorded while the quorum was broken
    replays verbatim after the quorum is restored (no contradiction)."""
    _quorum_policy(services, 2)
    alice = _signer(services, "alice", "k-alice")
    bob = _signer(services, "bob", "k-bob")
    signing, keys = services["signing"], services["keys"]
    signing.sign_artifact(alice, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-alice", request_id="s-alice",
                          signature_ttl=None)
    signing.sign_artifact(bob, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-bob", request_id="s-bob",
                          signature_ttl=None)
    assert _evaluate(services, "e-before")["decision"] == "pass"

    # Rotation alone now breaks the quorum: Alice's pre-rotation signature
    # no longer counts, with the individual reason visible in the ledger.
    rotated = keys.rotate(ADMIN, "k-alice", comment="scheduled rotation")
    new_key = rotated["active_key"]["key_id"]
    r = _evaluate(services, "e-rotated")
    assert r["decision"] == "deny"
    assert r["reason"] == "signature_quorum_not_met"
    quorum = r["signature_quorum"]
    assert quorum["required"] == 2
    assert quorum["counted"] == 1
    assert quorum["missing"] == 1
    assert quorum["counted_signers"] == ["bob"]
    rotated_entries = [x for x in quorum["rejected"]
                       if x["status"] == "rotated"]
    assert len(rotated_entries) == 1
    assert rotated_entries[0]["signed_by"] == "alice"
    assert rotated_entries[0]["key_id"] == "k-alice"
    assert rotated_entries[0]["reason"] == "signature_key_rotated"

    # An artifact carrying only old-key signatures cannot pass: rotate
    # Bob's key too -> counted falls to zero while records still exist.
    keys.rotate(ADMIN, "k-bob", comment="scheduled rotation")
    r_none = _evaluate(services, "e-all-rotated")
    assert r_none["decision"] == "deny"
    assert r_none["reason"] == "signature_quorum_not_met"
    assert r_none["signature_quorum"]["counted"] == 0
    assert r_none["signature_quorum"]["missing"] == 2
    assert {x["status"] for x in r_none["signature_quorum"]["rejected"]} \
        == {"rotated"}

    # Re-sign both artifacts' seats with the currently active keys.
    bob_new_key = services["store"].state["keys"]["k-bob"]["rotated_to"]
    keys.grant_signer(ADMIN, new_key, "alice")
    keys.grant_signer(ADMIN, bob_new_key, "bob")
    alice_new = Caller(id="alice", roles=("signer", "deployer"),
                       key_grants=(new_key,))
    bob_new = Caller(id="bob", roles=("signer", "deployer"),
                     key_grants=(bob_new_key,))
    signing.sign_artifact(alice_new, artifact_digest=DIGEST,
                          artifact_type=TYPE, key_id=new_key,
                          request_id="s-alice-new", signature_ttl=None)
    signing.sign_artifact(bob_new, artifact_digest=DIGEST,
                          artifact_type=TYPE, key_id=bob_new_key,
                          request_id="s-bob-new", signature_ttl=None)
    r2 = _evaluate(services, "e-resigned")
    assert r2["decision"] == "pass"
    assert r2["signature_quorum"]["counted"] == 2
    assert r2["signature_quorum"]["missing"] == 0
    assert sorted(r2["signature_quorum"]["counted_signers"]) == ["alice", "bob"]

    # History: all four signatures remain registered and queryable; the two
    # rotated records are listed alongside the active ones.
    listed = signing.get_signatures(DIGEST)["signatures"]
    assert len(listed) == 4
    assert {s["key_id"] for s in listed} == {
        "k-alice", "k-bob", new_key, bob_new_key}

    # The conclusion recorded while the quorum was broken is not contradicted
    # by the later re-signing: replay returns the stored deny verbatim.
    replay = services["admission"].replay("e-rotated")
    assert replay["result"]["decision"] == "deny"
    assert replay["result"]["reason"] == "signature_quorum_not_met"
    assert replay["result"]["signature_quorum"]["counted"] == 1
    replay_none = services["admission"].replay("e-all-rotated")
    assert replay_none["result"]["signature_quorum"]["counted"] == 0
    # Re-evaluating with the same request_id also replays the stored result.
    assert _evaluate(services, "e-rotated")["dedup"] is True


def test_resign_with_active_key_after_revocation_restores_quorum(services):
    """Revocation (existing behaviour, kept intact) also invalidates old
    signatures retroactively; re-signing with an active key restores them."""
    _quorum_policy(services, 2)
    alice = _signer(services, "alice", "k-alice")
    bob = _signer(services, "bob", "k-bob")
    signing, keys = services["signing"], services["keys"]
    signing.sign_artifact(alice, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-alice", request_id="s-alice",
                          signature_ttl=None)
    signing.sign_artifact(bob, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-bob", request_id="s-bob",
                          signature_ttl=None)
    assert _evaluate(services, "e-before")["decision"] == "pass"

    # Revoking the old key invalidates Alice's historical signature.
    keys.revoke(ADMIN, "k-alice", reason="suspected compromise")
    r = _evaluate(services, "e-revoked")
    assert r["decision"] == "deny"
    assert r["reason"] == "signature_quorum_not_met"
    assert r["signature_quorum"]["counted"] == 1
    assert any(x["status"] == "revoked"
               for x in r["signature_quorum"]["rejected"])

    # Re-sign with a fresh active key -> quorum restored.
    keys.generate(ADMIN, key_id="k-alice-replacement", ttl=None)
    keys.grant_signer(ADMIN, "k-alice-replacement", "alice")
    alice_new = Caller(id="alice", roles=("signer", "deployer"),
                       key_grants=("k-alice-replacement",))
    signing.sign_artifact(alice_new, artifact_digest=DIGEST,
                          artifact_type=TYPE, key_id="k-alice-replacement",
                          request_id="s-alice-new", signature_ttl=None)
    r2 = _evaluate(services, "e-resigned")
    assert r2["decision"] == "pass"
    assert r2["signature_quorum"]["counted"] == 2

    # History keeps both Alice records; the deny still replays as recorded.
    listed = signing.get_signatures(DIGEST)["signatures"]
    assert {s["key_id"] for s in listed} == {
        "k-alice", "k-bob", "k-alice-replacement"}
    replay = services["admission"].replay("e-revoked")
    assert replay["result"]["decision"] == "deny"
    assert replay["result"]["reason"] == "signature_quorum_not_met"


def test_grant_revocation_then_new_signer_fills_seat(services):
    _quorum_policy(services, 2)
    alice = _signer(services, "alice", "k-alice")
    bob = _signer(services, "bob", "k-bob")
    signing, keys = services["signing"], services["keys"]
    signing.sign_artifact(alice, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-alice", request_id="s-alice",
                          signature_ttl=None)
    signing.sign_artifact(bob, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-bob", request_id="s-bob",
                          signature_ttl=None)
    assert _evaluate(services, "e-ok")["decision"] == "pass"

    keys.revoke_signer_grant(ADMIN, "k-bob", "bob")
    r = _evaluate(services, "e-unauthorized")
    assert r["decision"] == "deny"
    assert r["reason"] == "signature_quorum_not_met"

    carol = _signer(services, "carol", "k-carol")
    signing.sign_artifact(carol, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-carol", request_id="s-carol",
                          signature_ttl=None)
    assert _evaluate(services, "e-carol")["decision"] == "pass"


def test_legacy_require_signature_policy_semantics_unchanged(services):
    """Old 'must have a signature' rules keep working: any one valid
    signature passes, and the deny reason stays the specific per-signature
    reason rather than the quorum code."""
    services["policy"].create_version(
        ADMIN,
        [PolicyRule(id="images", action=Decision.PASS,
                    match_types=(TYPE,), require_signature=True,
                    roles_allowed=("deployer",))],
        request_id="p-legacy", expected_version=0)
    alice = _signer(services, "alice", "k-alice")
    signing = services["signing"]
    signing.sign_artifact(alice, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-alice", request_id="s-alice",
                          signature_ttl=timedelta(days=1))

    # Expired single signature -> specific reason, as before.
    services["clock"].advance(timedelta(days=2))
    r = _evaluate(services, "e-legacy-expired")
    assert r["decision"] == "deny" and r["reason"] == "signature_expired"

    # A second, valid signature from another signer satisfies the old rule.
    bob = _signer(services, "bob", "k-bob")
    signing.sign_artifact(bob, artifact_digest=DIGEST, artifact_type=TYPE,
                          key_id="k-bob", request_id="s-bob",
                          signature_ttl=None)
    r2 = _evaluate(services, "e-legacy-pass")
    assert r2["decision"] == "pass"
    assert r2["signature_quorum"]["required"] == 1


def test_concurrent_distinct_signers_all_register(tmp_path):
    """Many signers racing to sign one artifact: every (signer, key) slot is
    registered exactly once and the quorum reflects all of them."""
    data_dir = str(tmp_path / "data")
    n_signers = 6

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
    for i in range(n_signers):
        keys.generate(ADMIN, key_id=f"k{i}", ttl=None)
        keys.grant_signer(ADMIN, f"k{i}", f"signer-{i}")

    def worker(i):
        _, signing = fresh()
        caller = Caller(id=f"signer-{i}", roles=("signer",),
                        key_grants=(f"k{i}",))
        # Each signer submits twice concurrently (retry) -> still one slot.
        return [signing.sign_artifact(
            caller, artifact_digest=DIGEST, artifact_type=TYPE,
            key_id=f"k{i}", request_id=f"req-{i}-{attempt}",
            signature_ttl=None) for attempt in (0, 1)]

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(n_signers)))

    store_after, signing_after = fresh()
    slots = store_after.state["signatures"][DIGEST]
    assert len(slots) == n_signers
    for first, second in results:
        assert first["signature"] == second["signature"]
        assert second["dedup"] is True

    from admission.engine import AdmissionService
    from admission.policy import PolicyService as PS
    adm = AdmissionService(store_after, FixedClock(), signing_after,
                           PS(store_after, FixedClock()))
    r = adm.evaluate(Caller(id="releaser", roles=("deployer",)),
                     artifact_digest=DIGEST, artifact_type=TYPE,
                     request_id="e-concurrent")
    assert r["decision"] == "pass"
    assert r["signature_quorum"]["counted"] == n_signers


def test_evaluation_log_shows_digest_and_quorum_basis(services, caplog):
    _quorum_policy(services, 2)
    alice = _signer(services, "alice", "k-alice")
    services["signing"].sign_artifact(
        alice, artifact_digest=DIGEST, artifact_type=TYPE,
        key_id="k-alice", request_id="s-alice", signature_ttl=None)

    with caplog.at_level(logging.INFO, logger="admission.engine"):
        r = _evaluate(services, "e-logged")
    assert r["reason"] == "signature_quorum_not_met"
    joined = "\n".join(rec.getMessage() for rec in caplog.records)
    assert DIGEST in joined          # input digest visible
    assert "quorum=1/2" in joined    # counted/required visible
    assert "decision=deny" in joined
