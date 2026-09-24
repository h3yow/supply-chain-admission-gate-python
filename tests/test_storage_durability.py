"""Crash recovery: torn append, stale snapshot, full log replay."""
from __future__ import annotations

import json
from datetime import timedelta

from admission.keys import KeyService
from admission.models import Caller
from admission.storage import Store


def test_reopen_replays_every_committed_event(tmp_data_dir, clock):
    store = Store(tmp_data_dir)
    admin = Caller(id="admin", roles=("key_admin", "policy_admin"))
    keys = KeyService(store, clock)
    keys.generate(admin, key_id="k1", ttl=timedelta(days=3))
    keys.rotate(admin, "k1")
    new_id = store.state["keys"]["k1"]["rotated_to"]
    keys.revoke(admin, new_id, reason="incident")
    keys.grant_signer(admin, "k1", "ci")

    committed = store.read_audit()
    assert len(committed) == 4  # generate, rotate(2 key effects/1 event), revoke, grant

    # A fresh Store must reconstruct identical state purely from the log.
    reopened = Store(tmp_data_dir)
    assert reopened.state["keys"] == store.state["keys"]
    assert reopened.state["key_grants"] == {"k1": ["ci"]}
    assert reopened.state["last_seq"] == store.state["last_seq"]


def test_torn_final_log_line_is_dropped_not_fatal(tmp_data_dir, clock):
    store = Store(tmp_data_dir)
    admin = Caller(id="admin", roles=("key_admin",))
    KeyService(store, clock).generate(admin, key_id="good", ttl=None)
    store._write_state_atomic(store.state)

    # Simulate a crash mid-append: a partial, non-parseable trailing line.
    with open(store._audit_path, "a", encoding="utf-8") as fh:
        fh.write('{"seq": 2, "event_type": "key_generat')
    reopened = Store(tmp_data_dir)
    assert "good" in reopened.state["keys"]
    assert reopened.state["last_seq"] == 1
    # Store keeps working and assigns the next seq after the last good event.
    KeyService(reopened, clock).generate(admin, key_id="good2", ttl=None)
    assert reopened.state["last_seq"] == 2
    assert set(reopened.state["keys"]) == {"good", "good2"}


def test_stale_snapshot_is_rebuilt_from_log(tmp_data_dir, clock):
    store = Store(tmp_data_dir)
    admin = Caller(id="admin", roles=("key_admin", "policy_admin"))
    keys = KeyService(store, clock)
    keys.generate(admin, key_id="k1", ttl=None)
    seq_after_generate = store.state["last_seq"]

    # Append more events, then rewrite state.json to an older snapshot (as if
    # the atomic snapshot write were lost after the durable log append).
    keys.rotate(admin, "k1")
    stale = json.loads(json.dumps(store.state))
    stale["last_seq"] = seq_after_generate
    stale["keys"] = {"k1": store.state["keys"]["k1"]}
    with open(store._state_path, "w", encoding="utf-8") as fh:
        json.dump(stale, fh)

    reopened = Store(tmp_data_dir)
    assert reopened.state["last_seq"] == store.state["last_seq"]
    rotated_to = reopened.state["keys"]["k1"]["rotated_to"]
    assert rotated_to in reopened.state["keys"]
    assert reopened.state["keys"]["k1"]["rotated_at"] is not None


def test_transaction_rollback_leaves_no_partial_state(tmp_data_dir, clock):
    store = Store(tmp_data_dir)
    try:
        with store.transaction() as state:
            # All state changes go through staged events (the only write path
            # used by the services); the event is staged but the body raises
            # before commit, so it must never reach the log or the projection.
            store.emit(state, {"event_type": "key_generated",
                               "occurred_at": "2026-06-01T00:00:00+00:00",
                               "actor": "a", "request_id": "phantom",
                               "payload": {"key": {"key_id": "phantom"}}})
            raise RuntimeError("boom mid-transaction")
    except RuntimeError:
        pass
    assert "phantom" not in store.state["keys"]
    assert store.read_audit() == []
    assert store.state["last_seq"] == 0
    # Clean state remains usable and survives reopen.
    reopened = Store(tmp_data_dir)
    assert reopened.state["keys"] == {}
    KeyService(reopened, clock).generate(
        Caller(id="admin", roles=("key_admin",)), key_id="real", ttl=None)
    assert "real" in Store(tmp_data_dir).state["keys"]
