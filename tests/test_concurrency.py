"""Concurrent submission / publish must never create duplicates or partial
state."""

import threading

from gate.errors import UnauthorizedCallerError
from gate.models import Artifact, Caller, Decision, PolicyRule, RuleEffect

SIGNER = Caller("signer-1", frozenset({"signer"}))


def test_concurrent_sign_submissions_register_once(service):
    image = Artifact(digest="sha256:concurrent", name="c", kind="container-image")
    barrier = threading.Barrier(8)
    results: list = []
    errors: list[Exception] = []

    def worker():
        barrier.wait()
        try:
            record, created = service.submit_signature(image, SIGNER)
            results.append((record.fingerprint(), created))
        except Exception as exc:  # only rejected auth should land here
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert len(service.store.signatures) == 1
    created_flags = [created for _, created in results]
    assert created_flags.count(True) == 1
    assert created_flags.count(False) == 7
    fingerprints = {fp for fp, _ in results}
    assert len(fingerprints) == 1

    submitted = service.audit_events("signature.submitted")
    assert len(submitted) == 8


def test_concurrent_policy_publishes_get_unique_versions(service):
    barrier = threading.Barrier(5)
    versions: list[int] = []

    def worker(i):
        barrier.wait()
        v = service.publish_policy(
            [
                PolicyRule(
                    name=f"rule-{i}",
                    artifact_kinds=frozenset({"*"}),
                    effect=RuleEffect.ALLOW,
                )
            ],
            author=f"admin-{i}",
        )
        versions.append(v)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(versions) == [2, 3, 4, 5, 6]
    stored = service.policies.list_versions()
    assert [p.version for p in stored] == [1, 2, 3, 4, 5, 6]
    published = service.audit_events("policy.published")
    assert len(published) == 6  # seed v1 + five concurrent publishes


def test_concurrent_evaluations_are_consistent(service, signed_image, deployer):
    barrier = threading.Barrier(10)
    outcomes: set[tuple] = set()

    def worker():
        barrier.wait()
        r = service.evaluate(signed_image, deployer)
        outcomes.add((r.decision.value, r.reason, r.evaluation_id))

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert outcomes == {("allow", None, service.evaluate(signed_image, deployer).evaluation_id)}


def test_concurrent_unauthorized_signers_register_nothing(service, image):
    bad = Caller("mallory", frozenset())
    barrier = threading.Barrier(4)
    errors: list[str] = []

    def worker():
        barrier.wait()
        try:
            service.submit_signature(image, bad)
        except UnauthorizedCallerError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == ["unauthorized_caller"] * 4
    assert len(service.store.signatures) == 0
