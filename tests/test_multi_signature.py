"""Multi-signature quorum: registration, counting, rotation and revocation."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from admission.clock import FixedClock
from admission.keys import KeyService
from admission.models import Caller, Decision, PolicyRule
from admission.signing import SigningService
from admission.storage import Store

ADMIN = Caller(id="admin", roles=("key_admin", "policy_admin"))
DEPLOYER = Caller(id="ci", roles=("deployer",))
DIGEST = "sha256:release-1"
ATYPE = "container-image"


def _signer(name: str, *key_ids: str) -> Caller:
    return Caller(id=name, roles=("signer",), key_grants=tuple(key_ids))


def _world(services, min_signatures: int, keys: dict[str, list[str]]):
    """Create keys + grants and a signed-image policy with the given quorum."""
    ksvc: KeyService = services["keys"]
    for key_id, signers in keys.items():
        ksvc.generate(ADMIN, key_id=key_id, ttl=None)
        for signer in signers:
            ksvc.grant_signer(ADMIN, key_id, signer)
    services["policy"].create_version(
        ADMIN,
        [PolicyRule(id="img", action=Decision.PASS, match_types=(ATYPE,),
                    require_signature=True, roles_allowed=("deployer",),
                    min_signatures=min_signatures)],
        request_id=f"p-quorum-{min_signatures}", expected_version=0)


def _evaluate(services, request_id: str):
    return services["admission"].evaluate(
        DEPLOYER, artifact_digest=DIGEST, artifact_type=ATYPE,
        request_id=request_id)


def test_quorum_exactly_met_passes(services):
    _world(services, 2, {"k1": ["alice"], "k2": ["bob"]})
    signing: SigningService = services["signing"]
    signing.sign_artifact(_signer("alice", "k1"), artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id="k1", request_id="s-a",
                          signature_ttl=None)
    signing.sign_artifact(_signer("bob", "k2"), artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id="k2", request_id="s-b",
                          signature_ttl=None)

    r = _evaluate(services, "e-pass")
    assert r["decision"] == "pass" and r["reason"] == "ok"
    report = r["signature_report"]
    assert (report["required"], report["counted"], report["missing"]) == (2, 2, 0)
    assert all(e["counted"] for e in report["entries"])
    # The gate trace names each signer, key and whether it counted.
    assert any("alice" in b and "counted=True" in b for b in r["basis"])
    assert any("bob" in b and "counted=True" in b for b in r["basis"])


def test_quorum_one_short_is_denied_and_distinguishable_from_missing(services):
    _world(services, 2, {"k1": ["alice"], "k2": ["bob"]})
    signing: SigningService = services["signing"]

    # No signatures at all -> signature_missing (not a quorum problem).
    r0 = _evaluate(services, "e-none")
    assert r0["decision"] == "deny" and r0["reason"] == "signature_missing"
    assert r0["signature_report"]["counted"] == 0
    assert r0["signature_report"]["entries"] == []

    # One of two required -> signature_quorum_not_met, a *different* result.
    signing.sign_artifact(_signer("alice", "k1"), artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id="k1", request_id="s-a",
                          signature_ttl=None)
    r1 = _evaluate(services, "e-short")
    assert r1["decision"] == "deny"
    assert r1["reason"] == "signature_quorum_not_met"
    assert r1["signature_status"] == "quorum_not_met"
    report = r1["signature_report"]
    assert (report["required"], report["counted"], report["missing"]) == (2, 1, 1)
    assert "requires 2 valid distinct-signer signatures" in r1["rationale"]
    counted_entry = next(e for e in report["entries"] if e["counted"])
    assert counted_entry["signature"]["signed_by"] == "alice"


def test_same_signer_cannot_fill_quorum_alone(services):
    _world(services, 2, {"k1": ["alice"], "k2": ["alice"]})
    signing: SigningService = services["signing"]
    alice_k1 = _signer("alice", "k1")
    alice_k2 = _signer("alice", "k2")

    first = signing.sign_artifact(alice_k1, artifact_digest=DIGEST,
                                  artifact_type=ATYPE, key_id="k1",
                                  request_id="s-a1", signature_ttl=None)
    assert first["dedup"] is False

    # Retry with the same key under a new request_id -> original record back.
    retry = signing.sign_artifact(alice_k1, artifact_digest=DIGEST,
                                  artifact_type=ATYPE, key_id="k1",
                                  request_id="s-a1-retry", signature_ttl=None)
    assert retry["dedup"] is True
    assert retry["signature"] == first["signature"]

    # Same signer with a *different* key registers, but still counts once.
    signing.sign_artifact(alice_k2, artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id="k2",
                          request_id="s-a2", signature_ttl=None)
    assert len(signing.list_signatures(DIGEST)) == 2

    r = _evaluate(services, "e-dup-signer")
    assert r["decision"] == "deny" and r["reason"] == "signature_quorum_not_met"
    report = r["signature_report"]
    assert (report["counted"], report["missing"]) == (1, 1)
    dup = next(e for e in report["entries"] if not e["counted"])
    assert dup["not_counted_reason"] == "duplicate_signer"


def test_same_key_shared_by_two_signers_counts_once(services):
    _world(services, 2, {"k1": ["alice", "bob"]})
    signing: SigningService = services["signing"]
    signing.sign_artifact(_signer("alice", "k1"), artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id="k1", request_id="s-a",
                          signature_ttl=None)
    signing.sign_artifact(_signer("bob", "k1"), artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id="k1", request_id="s-b",
                          signature_ttl=None)

    r = _evaluate(services, "e-shared-key")
    assert r["decision"] == "deny" and r["reason"] == "signature_quorum_not_met"
    report = r["signature_report"]
    assert report["counted"] == 1
    dup = next(e for e in report["entries"] if not e["counted"])
    assert dup["not_counted_reason"] == "duplicate_key"


def test_rotation_drops_signature_and_resign_with_new_key_refills(services):
    _world(services, 2, {"k1": ["alice"], "k2": ["bob"]})
    keys: KeyService = services["keys"]
    signing: SigningService = services["signing"]
    signing.sign_artifact(_signer("alice", "k1"), artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id="k1", request_id="s-a",
                          signature_ttl=None)
    signing.sign_artifact(_signer("bob", "k2"), artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id="k2", request_id="s-b",
                          signature_ttl=None)
    assert _evaluate(services, "e-before")["decision"] == "pass"

    # Rotating k2 retires bob's signature: quorum no longer met.
    rotated = keys.rotate(ADMIN, "k2")
    new_id = rotated["active_key"]["key_id"]
    r = _evaluate(services, "e-rotated")
    assert r["decision"] == "deny" and r["reason"] == "signature_quorum_not_met"
    report = r["signature_report"]
    assert (report["counted"], report["missing"]) == (1, 1)
    stale = next(e for e in report["entries"]
                 if e["signature"]["key_id"] == "k2")
    assert stale["status"] == "rotated"
    assert stale["not_counted_reason"] == "signature_key_rotated"

    # Bob re-signs the same artifact with the active successor key: the
    # historical record is kept, the quorum is refilled, no contradiction.
    keys.grant_signer(ADMIN, new_id, "bob")
    signing.sign_artifact(_signer("bob", new_id), artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id=new_id,
                          request_id="s-b-resign", signature_ttl=None)
    assert len(signing.list_signatures(DIGEST)) == 3
    r2 = _evaluate(services, "e-refilled")
    assert r2["decision"] == "pass"
    assert r2["signature_report"]["counted"] == 2


def test_revoked_signer_grant_drops_signature_until_regranted(services):
    _world(services, 2, {"k1": ["alice"], "k2": ["bob"]})
    keys: KeyService = services["keys"]
    signing: SigningService = services["signing"]
    signing.sign_artifact(_signer("alice", "k1"), artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id="k1", request_id="s-a",
                          signature_ttl=None)
    signing.sign_artifact(_signer("bob", "k2"), artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id="k2", request_id="s-b",
                          signature_ttl=None)
    assert _evaluate(services, "e-before")["decision"] == "pass"

    keys.revoke_signer_grant(ADMIN, "k2", "bob")
    r = _evaluate(services, "e-unauthorized")
    assert r["decision"] == "deny" and r["reason"] == "signature_quorum_not_met"
    entry = next(e for e in r["signature_report"]["entries"]
                 if e["signature"]["signed_by"] == "bob")
    assert entry["status"] == "unauthorized_caller"
    assert entry["not_counted_reason"] == "signature_unauthorized_caller"

    keys.grant_signer(ADMIN, "k2", "bob")
    assert _evaluate(services, "e-regranted")["decision"] == "pass"


def test_concurrent_distinct_signers_and_retry_storm(tmp_path):
    """Many signers race to sign one artifact while one signer retries:
    exactly one record per (signer, key), quorum met, no lost updates."""
    data_dir = str(tmp_path / "data")
    store = Store(data_dir)
    clock = FixedClock()
    keys = KeyService(store, clock)
    signers = [f"signer-{i}" for i in range(6)]
    for i, name in enumerate(signers):
        keys.generate(ADMIN, key_id=f"k{i}", ttl=None)
        keys.grant_signer(ADMIN, f"k{i}", name)

    def worker(i: int):
        # Each thread gets its own service objects over the shared store.
        s = Store(data_dir)
        k = KeyService(s, FixedClock())
        svc = SigningService(s, FixedClock(), k)
        return svc.sign_artifact(
            _signer(signers[i], f"k{i}"), artifact_digest=DIGEST,
            artifact_type=ATYPE, key_id=f"k{i}",
            request_id=f"race-{i}", signature_ttl=None)

    def retry_worker(attempt: int):
        s = Store(data_dir)
        k = KeyService(s, FixedClock())
        svc = SigningService(s, FixedClock(), k)
        return svc.sign_artifact(
            _signer(signers[0], "k0"), artifact_digest=DIGEST,
            artifact_type=ATYPE, key_id="k0",
            request_id=f"retry-{attempt}", signature_ttl=None)

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(worker, range(6)))
        retries = list(pool.map(retry_worker, range(8)))

    assert sum(1 for r in results if r["dedup"] is False) == 6
    assert all(r["dedup"] for r in retries)  # signer-0 already registered
    final = Store(data_dir)
    assert len(final.state["signatures"][DIGEST]) == 6

    # Quorum of 6 distinct signers is now satisfiable and counts each once.
    signing = SigningService(final, FixedClock(), KeyService(final, FixedClock()))
    report = signing.evaluate_signatures(DIGEST, ATYPE, required=6)
    assert report["status"] == "valid" and report["counted"] == 6
    types = [e["event_type"] for e in final.read_audit()]
    assert types.count("signature_registered") == 6


def test_legacy_single_signature_policy_semantics_unchanged(services):
    """require_signature without min_signatures behaves exactly as before."""
    _world(services, 1, {"k1": ["alice"]})
    signing: SigningService = services["signing"]

    r0 = _evaluate(services, "e-legacy-none")
    assert r0["decision"] == "deny" and r0["reason"] == "signature_missing"

    signing.sign_artifact(_signer("alice", "k1"), artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id="k1", request_id="s-a",
                          signature_ttl=None)
    r1 = _evaluate(services, "e-legacy-pass")
    assert r1["decision"] == "pass"
    assert r1["signature_report"]["required"] == 1

    # Old stored rules (no min_signatures field) hydrate with the default.
    raw = services["store"].state["policies"]["1"]["rules"][0]
    raw.pop("min_signatures", None)
    hydrated = services["policy"].get_version(1)
    assert hydrated.rules[0].min_signatures == 1


def test_expired_signature_reported_per_entry(services):
    _world(services, 2, {"k1": ["alice"], "k2": ["bob"]})
    signing: SigningService = services["signing"]
    clock = services["clock"]
    signing.sign_artifact(_signer("alice", "k1"), artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id="k1", request_id="s-a",
                          signature_ttl=timedelta(days=7))
    signing.sign_artifact(_signer("bob", "k2"), artifact_digest=DIGEST,
                          artifact_type=ATYPE, key_id="k2", request_id="s-b",
                          signature_ttl=None)
    assert _evaluate(services, "e-fresh")["decision"] == "pass"

    clock.advance(timedelta(days=8))
    r = _evaluate(services, "e-expired")
    assert r["decision"] == "deny" and r["reason"] == "signature_quorum_not_met"
    entries = {e["signature"]["signed_by"]: e
               for e in r["signature_report"]["entries"]}
    assert entries["alice"]["status"] == "expired"
    assert entries["alice"]["not_counted_reason"] == "signature_expired"
    assert entries["bob"]["counted"] is True
