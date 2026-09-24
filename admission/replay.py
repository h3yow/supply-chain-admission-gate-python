"""Project the append-only audit log into a state snapshot.

The audit log is the source of truth: any committed event survives crashes and
is reflected here; an event never committed (exception before append) never
existed in the first place. Because log lines are ordered and single-writer,
replaying them always yields the same state.

Services do NOT mutate the state dict directly; they stage events via
``Store.emit``. The same fold used to rebuild from scratch is applied to the
pending events at commit time, so ``state.json`` is always a pure projection
of the log prefix through ``last_seq``.
"""
from __future__ import annotations

from typing import Any

from admission.audit_event_types import (
    ADMISSION_EVALUATED,
    KEY_GENERATED,
    KEY_GRANT_REVOKED,
    KEY_GRANTED,
    KEY_REVOKED,
    KEY_ROTATED,
    POLICY_CREATED,
    POLICY_ROLLED_BACK,
    SIGNATURE_DEDUP_HIT,
    SIGNATURE_REGISTERED,
)


def empty_state() -> dict[str, Any]:
    return {
        "last_seq": 0,
        "current_policy_version": 0,
        "keys": {},          # key_id -> key record dict
        "key_grants": {},    # key_id -> [caller_ids] allowed to sign with it
        "signatures": {},    # artifact_digest -> signature record dict
        "policies": {},      # version(int as str) -> policy version dict
        "request_index": {}, # request_id -> {"seq": int, "kind": str, "result_key": str}
    }


def apply_events(state: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    """Fold ordered audit events into ``state`` (mutated and returned)."""
    for event in events:
        seq = int(event["seq"])
        kind = event["event_type"]
        payload = event.get("payload", {})
        request_id = event.get("request_id", "")

        if kind == KEY_GENERATED:
            key = payload["key"]
            state["keys"][key["key_id"]] = key

        elif kind == KEY_ROTATED:
            old = payload["old_key"]
            new = payload["new_key"]
            state["keys"][old["key_id"]] = old
            state["keys"][new["key_id"]] = new

        elif kind == KEY_REVOKED:
            key = payload["key"]
            state["keys"][key["key_id"]] = key

        elif kind == KEY_GRANTED:
            state["key_grants"].setdefault(payload["key_id"], [])
            if payload["caller_id"] not in state["key_grants"][payload["key_id"]]:
                state["key_grants"][payload["key_id"]].append(payload["caller_id"])

        elif kind == KEY_GRANT_REVOKED:
            grantees = state["key_grants"].get(payload["key_id"], [])
            state["key_grants"][payload["key_id"]] = [
                g for g in grantees if g != payload["caller_id"]
            ]

        elif kind == SIGNATURE_REGISTERED:
            sig = payload["signature"]
            state["signatures"][sig["artifact_digest"]] = sig
            state["request_index"][request_id] = {
                "seq": seq,
                "kind": "sign",
                "result_key": sig["artifact_digest"],
            }

        elif kind == SIGNATURE_DEDUP_HIT:
            state["request_index"][request_id] = {
                "seq": seq,
                "kind": "sign_dedup",
                "result_key": payload["artifact_digest"],
            }

        elif kind == POLICY_CREATED:
            policy = payload["policy"]
            version = str(policy["version"])
            state["policies"][version] = policy
            state["current_policy_version"] = policy["version"]
            state["request_index"][request_id] = {
                "seq": seq,
                "kind": "policy",
                "result_key": version,
            }

        elif kind == POLICY_ROLLED_BACK:
            new_policy = payload["new_policy"]
            version = str(new_policy["version"])
            state["policies"][version] = new_policy
            state["current_policy_version"] = new_policy["version"]
            state["request_index"][request_id] = {
                "seq": seq,
                "kind": "policy_rollback",
                "result_key": version,
            }

        elif kind == ADMISSION_EVALUATED:
            state["request_index"][request_id] = {
                "seq": seq,
                "kind": "evaluate",
                "result_key": payload["artifact_digest"],
            }

        state["last_seq"] = seq

    return state


def rebuild_state(events: list[dict[str, Any]]) -> dict[str, Any]:
    return apply_events(empty_state(), events)
