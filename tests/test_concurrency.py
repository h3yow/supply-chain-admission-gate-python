"""Concurrent submissions must not double-register or contradict state."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from admission.clock import FixedClock
from admission.engine import AdmissionService
from admission.keys import KeyService
from admission.models import AdmissionError, Caller, Decision, PolicyRule
from admission.policy import PolicyService
from admission.signing import SigningService

ADMIN = Caller(id="admin", roles=("key_admin", "policy_admin"))
CI = Caller(id="ci", roles=("signer", "deployer"), key_grants=("k1",))


def _fresh_services(data_dir):
    # Each thread gets its own service objects over the SAME file-backed store
    # path, like separate worker processes sharing the data directory.
    from admission.storage import Store
    store = Store(data_dir)
    clock = FixedClock()
    keys = KeyService(store, clock)
    signing = SigningService(store, clock, keys)
    policy = PolicyService(store, clock)
    admission = AdmissionService(store, clock, signing, policy)
    return store, signing, admission


def test_concurrent_sign_same_request_id_registers_once(tmp_path):
    data_dir = str(tmp_path / "data")
    # seed key + grant through one "worker"
    store, signing, admission = _fresh_services(data_dir)
    store  # noqa
    keys = KeyService(store, FixedClock())
    keys.generate(ADMIN, key_id="k1", ttl=None)
    keys.grant_signer(ADMIN, "k1", "ci")
    del signing, admission

    results: list[dict | Exception] = []

    def worker():
        _, signing, _ = _fresh_services(data_dir)
        try:
            return signing.sign_artifact(
                CI, artifact_digest="sha256:hot",
                artifact_type="container-image", key_id="k1",
                request_id="same-request-id", signature_ttl=None)
        except AdmissionError as exc:  # pragma: no cover - reported below
            return exc

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: worker(), range(16)))

    assert not any(isinstance(r, Exception) for r in results), results
    assert all(r["artifact_digest"] == "sha256:hot" for r in results)
    signatures = [r["signature"] for r in results]
    assert len(set(signatures)) == 1  # every response is the same record

    store_after, _, _ = _fresh_services(data_dir)
    assert len(store_after.state["signatures"]) == 1
    types = [e["event_type"] for e in store_after.read_audit()]
    assert types.count("signature_registered") == 1
    assert types.count("signature_dedup_hit") == 15


def test_concurrent_sign_distinct_request_ids_same_signer_key_dedup(tmp_path):
    """Same signer + same key + same artifact, distinct request_ids racing:
    exactly one registration wins, every other submission dedups onto it and
    receives the same record — never a conflict, never a second signature."""
    data_dir = str(tmp_path / "data2")
    store = __import__("admission.storage", fromlist=["Store"]).Store(data_dir)
    keys = KeyService(store, FixedClock())
    keys.generate(ADMIN, key_id="k1", ttl=None)
    keys.grant_signer(ADMIN, "k1", "ci")

    results: list[dict] = []
    errors: list[str] = []
    lock = threading.Lock()

    def worker(idx):
        _, signing, _ = _fresh_services(data_dir)
        try:
            record = signing.sign_artifact(
                CI, artifact_digest="sha256:once",
                artifact_type="container-image", key_id="k1",
                request_id=f"distinct-{idx}", signature_ttl=None)
            with lock:
                results.append(record)
        except AdmissionError as exc:  # pragma: no cover - reported below
            with lock:
                errors.append(exc.error_code.value)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(12)))

    assert not errors, errors
    # Every caller observes the same single signature record.
    assert len({r["signature"] for r in results}) == 1
    assert sum(1 for r in results if r["dedup"]) == 11
    store_after, _, _ = _fresh_services(data_dir)
    assert len(store_after.state["signatures"]) == 1
    assert len(store_after.state["signatures"]["sha256:once"]) == 1
    types = [e["event_type"] for e in store_after.read_audit()]
    assert types.count("signature_registered") == 1
    assert types.count("signature_dedup_hit") == 11


def test_concurrent_evaluations_same_request_id_are_identical(tmp_path):
    data_dir = str(tmp_path / "data3")
    store, _signing, _admission = _fresh_services(data_dir)
    PolicyService(store, FixedClock()).create_version(
        ADMIN, [PolicyRule(id="img", action=Decision.PASS,
                           match_types=("container-image",))],
        request_id="p1", expected_version=0)

    def evaluate():
        _, _, adm = _fresh_services(data_dir)
        return adm.evaluate(
            CI, artifact_digest="sha256:e", artifact_type="container-image",
            request_id="stable-eval")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: evaluate(), range(10)))

    decisions = {r["decision"] for r in results}
    assert decisions == {"pass"}
    evaluated_at = {r["evaluated_at"] for r in results}
    assert evaluated_at == {results[0]["evaluated_at"]}
    store_after, _, _ = _fresh_services(data_dir)
    assert [e["event_type"] for e in store_after.read_audit()
            ].count("admission_evaluated") == 1


def test_concurrent_policy_creates_get_distinct_sequential_versions(tmp_path):
    data_dir = str(tmp_path / "data4")

    def worker(idx):
        from admission.storage import Store
        svc = PolicyService(Store(data_dir), FixedClock())
        try:
            svc.create_version(
                Caller(id="admin", roles=("policy_admin",)),
                [PolicyRule(id=f"r{idx}", action=Decision.PASS)],
                request_id=f"policy-{idx}")
        except AdmissionError as exc:
            return exc.error_code.value
        return "created"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(worker, range(6)))

    # Without optimistic pins every create is accepted; versions are assigned
    # serially, never duplicated.
    assert outcomes.count("created") == 6, outcomes
    from admission.storage import Store
    store = Store(data_dir)
    versions = sorted(store.state["policies"].keys(), key=int)
    assert versions == ["1", "2", "3", "4", "5", "6"]
    assert store.state["current_policy_version"] == 6


def test_optimistic_version_conflict_blocks_lost_update(tmp_path):
    data_dir = str(tmp_path / "data5")
    from admission.storage import Store
    s1 = Store(data_dir)
    s2 = Store(data_dir)
    p1 = PolicyService(s1, FixedClock())
    p2 = PolicyService(s2, FixedClock())
    admin = Caller(id="admin", roles=("policy_admin",))
    p1.create_version(admin, [PolicyRule(id="a", action=Decision.PASS)],
                      expected_version=0, request_id="p-a")
    # p2 still believes current is 0 -> its pinned write must fail.
    with pytest.raises(AdmissionError) as exc:
        p2.create_version(admin, [PolicyRule(id="b", action=Decision.DENY)],
                          expected_version=0, request_id="p-b")
    assert exc.value.error_code.value == "policy_version_conflict"
    # Reopening store2 makes it observe v1, then the write succeeds as v2.
    p2b = PolicyService(Store(data_dir), FixedClock())
    out = p2b.create_version(admin, [PolicyRule(id="b", action=Decision.DENY)],
                             expected_version=1, request_id="p-b2")
    assert out["version"] == 2
