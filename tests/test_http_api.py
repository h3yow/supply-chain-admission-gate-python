"""HTTP-level integration: happy path and distinguishable error mapping."""
from __future__ import annotations


def _signed_image_world(client, actors):
    r = client.post("/admin/keys", json={"key_id": "k1", "ttl_days": None},
                    headers=actors["admin"])
    assert r.status_code == 200, r.text
    assert client.post("/admin/keys/k1/grants", json={"signer_id": "ci"},
                       headers=actors["admin"]).status_code == 200
    r = client.post("/admin/policies", headers=actors["admin"], json={
        "expected_version": 0, "request_id": "p1",
        "rules": [{"id": "images", "action": "pass",
                   "match_types": ["container-image"],
                   "require_signature": True,
                   "roles_allowed": ["deployer"]}]})
    assert r.status_code == 200, r.text


def test_error_codes_map_to_distinct_http_statuses(client, actors):
    # 401 missing identity
    r = client.post("/admin/keys", json={})
    assert r.status_code == 401 and r.json()["error"] == "caller_required"

    # 403 wrong role
    r = client.post("/admin/keys", json={"key_id": "k1"}, headers=actors["viewer"])
    assert r.status_code == 403 and r.json()["error"] == "permission_denied"

    _signed_image_world(client, actors)

    # 404 replay of unknown request
    r = client.get("/admission/replay/never")
    assert r.status_code == 404 and r.json()["error"] == "nothing_to_replay"

    # 404 unknown key on rotate
    r = client.post("/admin/keys/nope/rotate", headers=actors["admin"])
    assert r.status_code == 404 and r.json()["error"] == "key_not_found"

    # 409 duplicate key
    r = client.post("/admin/keys", json={"key_id": "k1", "ttl_days": None},
                    headers=actors["admin"])
    assert r.status_code == 409 and r.json()["error"] == "key_exists"


def test_full_admission_flow_over_http(client, actors):
    _signed_image_world(client, actors)

    # unsigned -> deny signature_missing
    r = client.post("/admission/evaluate", headers=actors["ci"], json={
        "artifact_digest": "sha256:img1", "artifact_type": "container-image",
        "request_id": "eval-1"})
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "deny" and body["reason"] == "signature_missing"
    assert body["basis"] and body["rationale"]

    # unauthorized caller cannot sign
    r = client.post("/signatures", headers=actors["evil"], json={
        "artifact_digest": "sha256:img1", "artifact_type": "container-image",
        "key_id": "k1", "request_id": "sign-evil", "ttl_days": None})
    assert r.status_code == 403 and r.json()["error"] == "permission_denied"

    # authorized sign
    r = client.post("/signatures", headers=actors["ci"], json={
        "artifact_digest": "sha256:img1", "artifact_type": "container-image",
        "key_id": "k1", "request_id": "sign-1", "ttl_days": None})
    assert r.status_code == 200 and r.json()["dedup"] is False

    # retry -> same signature, dedup flag
    r = client.post("/signatures", headers=actors["ci"], json={
        "artifact_digest": "sha256:img1", "artifact_type": "container-image",
        "key_id": "k1", "request_id": "sign-1", "ttl_days": None})
    assert r.status_code == 200 and r.json()["dedup"] is True

    # pass now
    r = client.post("/admission/evaluate", headers=actors["ci"], json={
        "artifact_digest": "sha256:img1", "artifact_type": "container-image",
        "request_id": "eval-2"})
    assert r.json()["decision"] == "pass"

    # anonymous -> identity_unknown (identity header optional at endpoint)
    r = client.post("/admission/evaluate", headers=actors["anonymous"], json={
        "artifact_digest": "sha256:img1", "artifact_type": "container-image",
        "request_id": "eval-3"})
    assert r.json()["decision"] == "deny"
    assert r.json()["reason"] == "identity_unknown"

    # replay endpoint returns the stored conclusion
    r = client.get("/admission/replay/eval-2")
    assert r.status_code == 200
    assert r.json()["result"]["decision"] == "pass"
    assert r.json()["replayed"] is True

    # audit filter by type and request
    r = client.get("/audit", params={"event_type": "signature_registered"})
    assert r.json()["count"] == 1
    r = client.get("/audit", params={"request_id": "eval-2"})
    assert r.json()["count"] == 1


def test_policy_rotation_and_rollback_over_http(client, actors):
    _signed_image_world(client, actors)
    # concurrent-policy optimistic conflict
    r = client.post("/admin/policies", headers=actors["admin"], json={
        "expected_version": 0, "request_id": "stale",
        "rules": [{"id": "x", "action": "deny"}]})
    assert r.status_code == 409 and r.json()["error"] == "policy_version_conflict"

    # v2 deny
    r = client.post("/admin/policies", headers=actors["admin"], json={
        "expected_version": 1, "request_id": "p2",
        "rules": [{"id": "images", "action": "deny",
                   "match_types": ["container-image"]}]})
    assert r.status_code == 200 and r.json()["version"] == 2

    # rollback to v1
    r = client.post("/admin/policies/rollback", headers=actors["admin"],
                    json={"target_version": 1, "request_id": "rb1"})
    assert r.status_code == 200 and r.json()["version"] == 3
    assert "rollback to v1" in r.json()["comment"]

    listing = client.get("/admin/policies").json()["versions"]
    assert [v["version"] for v in listing] == [1, 2, 3]


def test_key_rotation_over_http_invalidates_future_use(client, actors):
    _signed_image_world(client, actors)
    r = client.post("/admin/keys/k1/rotate", headers=actors["admin"])
    assert r.status_code == 200
    new_id = r.json()["active_key"]["key_id"]
    assert r.json()["rotated_from"]["status"] == "rotated"

    # signing with old key after rotation -> 409 key_rotated
    r = client.post("/signatures", headers=actors["ci"], json={
        "artifact_digest": "sha256:z", "artifact_type": "container-image",
        "key_id": "k1", "request_id": "s-old", "ttl_days": None})
    assert r.status_code == 409 and r.json()["error"] == "key_rotated"

    # new key needs a grant first
    ci_headers = dict(actors["ci"])
    ci_headers["X-Caller-Key-Grants"] = new_id
    r = client.post("/signatures", headers=ci_headers, json={
        "artifact_digest": "sha256:z", "artifact_type": "container-image",
        "key_id": new_id, "request_id": "s-new", "ttl_days": None})
    assert r.status_code == 403 and r.json()["error"] == "permission_denied"

    assert client.post(f"/admin/keys/{new_id}/grants",
                       json={"signer_id": "ci"},
                       headers=actors["admin"]).status_code == 200
    r = client.post("/signatures", headers=ci_headers, json={
        "artifact_digest": "sha256:z", "artifact_type": "container-image",
        "key_id": new_id, "request_id": "s-new2", "ttl_days": None})
    assert r.status_code == 200


def test_multi_signature_quorum_over_http(client, actors):
    admin = actors["admin"]
    for key_id, signer in (("k1", "alice"), ("k2", "bob")):
        assert client.post("/admin/keys", json={"key_id": key_id,
                                                "ttl_days": None},
                           headers=admin).status_code == 200
        assert client.post(f"/admin/keys/{key_id}/grants",
                           json={"signer_id": signer},
                           headers=admin).status_code == 200
    r = client.post("/admin/policies", headers=admin, json={
        "expected_version": 0, "request_id": "p1",
        "rules": [{"id": "images", "action": "pass",
                   "match_types": ["container-image"],
                   "require_signature": True, "min_signatures": 2,
                   "roles_allowed": ["deployer"]}]})
    assert r.status_code == 200, r.text

    alice = {"X-Caller-Id": "alice", "X-Caller-Roles": "signer,deployer",
             "X-Caller-Key-Grants": "k1"}
    bob = {"X-Caller-Id": "bob", "X-Caller-Roles": "signer",
           "X-Caller-Key-Grants": "k2"}

    def evaluate(request_id):
        return client.post("/admission/evaluate", headers=alice, json={
            "artifact_digest": "sha256:img9",
            "artifact_type": "container-image",
            "request_id": request_id}).json()

    # One signature short of the quorum.
    assert client.post("/signatures", headers=alice, json={
        "artifact_digest": "sha256:img9", "artifact_type": "container-image",
        "key_id": "k1", "request_id": "s-a", "ttl_days": None}
        ).status_code == 200
    body = evaluate("e-short")
    assert body["decision"] == "deny"
    assert body["reason"] == "signature_quorum_not_met"
    assert body["signature_report"]["missing"] == 1

    # Second distinct signer fills the quorum.
    assert client.post("/signatures", headers=bob, json={
        "artifact_digest": "sha256:img9", "artifact_type": "container-image",
        "key_id": "k2", "request_id": "s-b", "ttl_days": None}
        ).status_code == 200
    assert evaluate("e-full")["decision"] == "pass"

    # Both registrations are queryable per artifact.
    r = client.get("/signatures/sha256:img9")
    assert r.status_code == 200
    assert {s["signed_by"] for s in r.json()["signatures"]} == {"alice", "bob"}
