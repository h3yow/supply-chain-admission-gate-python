"""Runnable local demo of the admission gate (no HTTP server needed).

Walks one artifact through: policy publish -> unsigned deny -> sign -> pass ->
signature expiry -> key rotation -> policy deny -> rollback -> replay. Prints
the input summary and decision basis at every step.

Run:  uv run python demo.py
"""
from __future__ import annotations

import json
import tempfile
from datetime import timedelta

from admission.clock import FixedClock
from admission.engine import AdmissionService
from admission.keys import KeyService
from admission.models import Caller, Decision, PolicyRule
from admission.policy import PolicyService
from admission.signing import SigningService
from admission.storage import Store

ADMIN = Caller(id="alice-admin", roles=("key_admin", "policy_admin"))
CI = Caller(id="ci-bot", roles=("signer", "deployer"), key_grants=("k1",))
ARTIFACT = ("sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "container-image")


def show(title: str, result: dict) -> None:
    print(f"\n=== {title} ===")
    print(f"decision={result['decision']:<14} reason={result['reason']} "
          f"policy_v{result['policy_version']} rule={result['rule_id']} "
          f"sig={result['signature_status']}")
    print("rationale:", result["rationale"])
    for line in result["basis"]:
        print("   -", line)


def main() -> None:
    data_dir = tempfile.mkdtemp(prefix="admission-demo-")
    clock = FixedClock()
    store = Store(data_dir)
    keys = KeyService(store, clock)
    signing = SigningService(store, clock, keys)
    policy = PolicyService(store, clock)
    admission = AdmissionService(store, clock, signing, policy)

    print(f"# local data dir: {data_dir}")

    # 1. Policy v1: signed container images from deployers pass.
    policy.create_version(ADMIN, [PolicyRule(
        id="signed-images", action=Decision.PASS,
        match_types=("container-image",),
        require_signature=True, roles_allowed=("deployer",))],
        comment="initial policy: require signed images",
        expected_version=0, request_id="demo-p1")

    show("1. Evaluate before signing", admission.evaluate(
        CI, artifact_digest=ARTIFACT[0], artifact_type=ARTIFACT[1],
        request_id="demo-e1"))

    # 2. Generate a key, grant the CI bot, sign.
    key = keys.generate(ADMIN, key_id="k1", ttl=None)
    print(f"\n2. generated key k1 (secret prefix {key['secret'][:8]}...)")
    keys.grant_signer(ADMIN, "k1", "ci-bot")
    signing.sign_artifact(CI, artifact_digest=ARTIFACT[0],
                          artifact_type=ARTIFACT[1], key_id="k1",
                          request_id="demo-s1", signature_ttl=timedelta(days=7))
    show("3. Evaluate after valid signing", admission.evaluate(
        CI, artifact_digest=ARTIFACT[0], artifact_type=ARTIFACT[1],
        request_id="demo-e2"))

    # 3. Time passes beyond TTL.
    clock.advance(timedelta(days=8))
    show("4. Evaluate after signature expiry", admission.evaluate(
        CI, artifact_digest=ARTIFACT[0], artifact_type=ARTIFACT[1],
        request_id="demo-e3"))

    # 4. Rotate key; old pre-rotation signature status explained.
    clock.advance(timedelta(days=-8))
    rotated = keys.rotate(ADMIN, "k1", comment="quarterly rotation")
    print(f"\n5. rotated k1 -> {rotated['active_key']['key_id']}; "
          f"pre-rotation signature stays valid")

    # 5. Policy v2 denies; then roll back to v1.
    policy.create_version(ADMIN, [PolicyRule(
        id="signed-images", action=Decision.DENY,
        match_types=("container-image",), require_signature=True,
        roles_allowed=("deployer",))],
        comment="incident freeze", request_id="demo-p2")
    show("6. Evaluate under deny policy v2", admission.evaluate(
        CI, artifact_digest=ARTIFACT[0], artifact_type=ARTIFACT[1],
        request_id="demo-e4"))
    policy.rollback(ADMIN, 1, comment="incident cleared", request_id="demo-rb1")

    # 6. Replay the original pass verbatim.
    replayed = admission.replay("demo-e2")
    print("\n7. Replay of request demo-e2 (originally recorded under v1):")
    print(json.dumps(replayed["result"], indent=2, ensure_ascii=False))

    # 7. Multi-signer quorum: v3 requires 2 distinct signers for images.
    policy.create_version(ADMIN, [PolicyRule(
        id="signed-images", action=Decision.PASS,
        match_types=("container-image",), min_signatures=2,
        roles_allowed=("deployer",))],
        comment="require two distinct signers", request_id="demo-p3")
    artifact2 = ("sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                 "container-image")
    # ci-bot re-signs with the rotated (currently active) key; qa-bot signs
    # with its own key. One signer alone is not enough.
    new_key = rotated["active_key"]["key_id"]
    keys.grant_signer(ADMIN, new_key, "ci-bot")
    ci_new = Caller(id="ci-bot", roles=("signer", "deployer"),
                    key_grants=(new_key,))
    keys.generate(ADMIN, key_id="k2", ttl=None)
    keys.grant_signer(ADMIN, "k2", "qa-bot")
    qa = Caller(id="qa-bot", roles=("signer",), key_grants=("k2",))

    signing.sign_artifact(ci_new, artifact_digest=artifact2[0],
                          artifact_type=artifact2[1], key_id=new_key,
                          request_id="demo-s2", signature_ttl=None)
    show("8. Quorum 2, only one signer", admission.evaluate(
        CI, artifact_digest=artifact2[0], artifact_type=artifact2[1],
        request_id="demo-e5"))
    signing.sign_artifact(qa, artifact_digest=artifact2[0],
                          artifact_type=artifact2[1], key_id="k2",
                          request_id="demo-s3", signature_ttl=None)
    show("9. Quorum 2, two distinct signers", admission.evaluate(
        CI, artifact_digest=artifact2[0], artifact_type=artifact2[1],
        request_id="demo-e6"))

    print(f"\n# audit events persisted: {len(store.read_audit())} in {data_dir}/audit.log")


if __name__ == "__main__":
    main()
