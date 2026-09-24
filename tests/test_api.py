"""End-to-end HTTP behavior and error-code -> HTTP status mapping."""

import pytest
from fastapi.testclient import TestClient

from gate.api import create_app
from gate.models import Decision, PolicyRule, RuleEffect
from gate.service import AdmissionService

ADMIN = {"identity": "admin", "roles": ["admin"]}
SIGNER = {"identity": "signer-1", "roles": ["signer"]}
DEPLOYER = {"identity": "deployer-1", "roles": ["deployer"]}
GUEST = {"identity": "guest", "roles": []}

IMAGE_ARTIFACT = {
    "digest": "sha256:abc",
    "name": "app:1",
    "kind": "container-image",
    "properties": {},
}


@pytest.fixture
def client():
    service = AdmissionService(signature_ttl=100.0)
    service.bootstrap_key()
    service.publish_policy(
        [
            PolicyRule(
                name="signed-images",
                artifact_kinds=frozenset({"container-image"}),
                effect=RuleEffect.ALLOW,
                require_roles=frozenset({"deployer"}),
                require_signature=True,
            )
        ],
        author="tester",
        on_unmatched=Decision.MANUAL_REVIEW,
    )
    return TestClient(create_app(service))


def _evaluate(client, caller=DEPLOYER, version=None, artifact=IMAGE_ARTIFACT):
    body = {"artifact": artifact, "caller": caller}
    if version is not None:
        body["policy_version"] = version
    return client.post("/admission/evaluate", json=body)


def test_health(client):
    data = client.get("/health").json()
    assert data["status"] == "ok"
    assert data["current_policy_version"] == 1


def test_full_sign_then_allow_flow(client):
    # unsigned -> denied for signature reason
    resp = _evaluate(client)
    assert resp.status_code == 200
    assert resp.json()["reason"] == "signature_invalid"

    # non-signer is forbidden from signing
    forbidden = client.post(
        "/artifacts/sign", json={"artifact": IMAGE_ARTIFACT, "caller": DEPLOYER}
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["error"] == "unauthorized_caller"

    # authorized signer registers the signature
    signed = client.post(
        "/artifacts/sign", json={"artifact": IMAGE_ARTIFACT, "caller": SIGNER}
    )
    assert signed.status_code == 200
    assert signed.json()["created"] is True

    # retry is idempotent
    retry = client.post(
        "/artifacts/sign", json={"artifact": IMAGE_ARTIFACT, "caller": SIGNER}
    )
    assert retry.json()["created"] is False

    # deployer now allowed; guest is denied for role reasons
    assert _evaluate(client).json()["decision"] == "allow"
    guest = _evaluate(client, caller=GUEST)
    assert guest.json()["reason"] == "unauthorized_caller"


def test_not_covered_is_review(client):
    mystery = {"digest": "sha256:x", "name": "x", "kind": "firmware", "properties": {}}
    resp = _evaluate(client, artifact=mystery)
    body = resp.json()
    assert body["decision"] == "manual_review"
    assert body["reason"] == "policy_not_covered"


def test_missing_policy_version_is_404(client):
    resp = _evaluate(client, version=99)
    assert resp.status_code == 404
    assert resp.json()["error"] == "policy_not_covered"


def test_key_rotation_invalidates_signature_over_http(client):
    client.post("/artifacts/sign", json={"artifact": IMAGE_ARTIFACT, "caller": SIGNER})
    assert _evaluate(client).json()["decision"] == "allow"

    forbidden = client.post(
        "/keys/rotate", json={"caller": DEPLOYER}
    )
    assert forbidden.status_code == 403

    rotated = client.post("/keys/rotate", json={"caller": ADMIN})
    assert rotated.status_code == 200

    body = _evaluate(client).json()
    assert body["decision"] == "deny"
    assert body["reason"] == "signature_invalid"


def test_policy_publish_rollback_and_audit(client):
    mystery = {"digest": "sha256:m", "name": "m", "kind": "firmware", "properties": {}}
    assert _evaluate(client, artifact=mystery).json()["decision"] == "manual_review"

    published = client.post(
        "/policy/publish",
        json={
            "rules": [
                {
                    "name": "all",
                    "artifact_kinds": ["*"],
                    "effect": "allow",
                    "require_roles": ["deployer"],
                }
            ],
            "caller": ADMIN,
            "note": "open",
        },
    )
    assert published.json()["version"] == 2
    assert _evaluate(client, artifact=mystery).json()["decision"] == "allow"

    rolled_back = client.post(
        "/policy/rollback", json={"version": 1, "caller": ADMIN}
    )
    assert rolled_back.json() == {"version": 3}
    assert _evaluate(client, artifact=mystery).json()["decision"] == "manual_review"

    audit = client.get("/audit?event_type=policy.rolled_back").json()
    assert len(audit) == 1
    assert audit[0]["payload"]["from_version"] == 1
