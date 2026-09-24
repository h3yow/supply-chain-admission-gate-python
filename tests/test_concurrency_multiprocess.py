"""Cross-process concurrency: real OS processes sharing one data directory.

Validates the fcntl flock path (the in-process global lock cannot help here):
N processes sign the same artifact with the same idempotency key.
"""
from __future__ import annotations

import multiprocessing as mp

from admission.clock import FixedClock
from admission.keys import KeyService
from admission.models import Caller
from admission.signing import SigningService
from admission.storage import Store


def _sign_worker(data_dir: str, request_id: str, queue) -> None:
    try:
        store = Store(data_dir)
        ci = Caller(id="ci", roles=("signer",), key_grants=("k1",))
        keys = KeyService(store, FixedClock())
        signing = SigningService(store, FixedClock(), keys)
        record = signing.sign_artifact(
            ci, artifact_digest="sha256:multi",
            artifact_type="container-image", key_id="k1",
            request_id=request_id, signature_ttl=None)
        queue.put(("ok", record["signature"]))
    except Exception as exc:
        queue.put(("error", repr(exc)))


def test_multiple_processes_signing_same_request_id(tmp_path):
    ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() \
        else mp.get_context("spawn")
    data_dir = str(tmp_path / "data")
    store = Store(data_dir)
    keys = KeyService(store, FixedClock())
    admin = Caller(id="admin", roles=("key_admin",))
    keys.generate(admin, key_id="k1", ttl=None)
    keys.grant_signer(admin, "k1", "ci")

    queue = ctx.Queue()
    procs = [
        ctx.Process(target=_sign_worker, args=(data_dir, "shared-req", queue))
        for _ in range(4)
    ]
    for p in procs:
        p.start()
    outcomes = [queue.get() for _ in procs]
    for p in procs:
        p.join()
        assert p.exitcode == 0, outcomes

    assert all(kind == "ok" for kind, _ in outcomes), outcomes
    assert len({sig for _, sig in outcomes}) == 1

    final = Store(data_dir)
    assert len(final.state["signatures"]) == 1
    types = [e["event_type"] for e in final.read_audit()]
    assert types.count("signature_registered") == 1
    assert types.count("signature_dedup_hit") == 3
