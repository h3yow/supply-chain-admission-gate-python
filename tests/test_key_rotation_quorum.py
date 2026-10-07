# ruff: noqa: RUF002, RUF003  # 中文文档字符串/注释中的全角标点
"""Key rotation vs. the multi-signer quorum (release-flow scenarios).

Business coverage (each test name states the business case; run with
``pytest tests/test_key_rotation_quorum.py -v -o log_cli=true`` to see each
case and its admission log line):

1. 旧钥签名在轮换后立即不再计数 — 即使签名登记在轮换之前。
2. 只剩旧钥签名的制品不能被直接放行；结论里能看到 required/counted/missing
   以及每条失效签名的原因（signature_key_rotated）。
3. 轮换后用当前活跃密钥补签，可以把门槛重新凑齐。
4. 刚好凑齐门槛即放行；差一个签名仍拒绝（quorum_not_met）。
5. 同一签名方用同一把密钥重复/重试签名只算一份。
6. 并发或重试登记多条签名不重复计数、不错乱（线程 + request_id 重试）。
7. 旧钥历史签名仍可查询，且不与新签名冲突；已记录结论重放保持原样。
8. 旧的 require_signature 单签策略语义不因轮换改动而改变：旧钥签名轮换后
   不再算数（deny/signature_key_rotated），补签后恢复放行。
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from admission.clock import FixedClock
from admission.keys import KeyService
from admission.models import Caller, Decision, PolicyRule
from admission.policy import PolicyService
from admission.signing import SigningService
from admission.storage import Store

ADMIN = Caller(id="admin", roles=("key_admin", "policy_admin"))
DEPLOYER = Caller(id="releaser", roles=("deployer",))
DIGEST = "sha256:rotation-flow"
TYPE = "container-image"


def _make_signer(services, signer_id: str, key_id: str) -> Caller:
    keys: KeyService = services["keys"]
    if key_id not in services["store"].state["keys"]:
        keys.generate(ADMIN, key_id=key_id, ttl=None)
    keys.grant_signer(ADMIN, key_id, signer_id)
    return Caller(id=signer_id, roles=("signer", "deployer"), key_grants=(key_id,))


def _quorum_policy(services, min_signatures: int, request_id: str = "p-rotation") -> None:
    services["policy"].create_version(
        ADMIN,
        [
            PolicyRule(
                id="images",
                action=Decision.PASS,
                match_types=(TYPE,),
                min_signatures=min_signatures,
                roles_allowed=("deployer",),
            )
        ],
        request_id=request_id,
        expected_version=0,
    )


def _sign(services, caller, key_id: str, request_id: str) -> dict:
    return services["signing"].sign_artifact(
        caller,
        artifact_digest=DIGEST,
        artifact_type=TYPE,
        key_id=key_id,
        request_id=request_id,
        signature_ttl=None,
    )


def _evaluate(services, request_id: str) -> dict:
    return services["admission"].evaluate(
        DEPLOYER, artifact_digest=DIGEST, artifact_type=TYPE, request_id=request_id
    )


def test_01_rotation_invalidates_old_key_signatures_immediately(services):
    """业务1: 密钥一被轮换，旧钥登记过的签名（即使签于轮换之前）立即不算数，
    结论账本逐条给出 rotated / signature_key_rotated 原因。"""
    _quorum_policy(services, 2)
    alice = _make_signer(services, "alice", "k-alice")
    bob = _make_signer(services, "bob", "k-bob")
    _sign(services, alice, "k-alice", "s-alice")
    _sign(services, bob, "k-bob", "s-bob")
    assert _evaluate(services, "e-before")["decision"] == "pass"

    services["keys"].rotate(ADMIN, "k-alice", comment="release rotation")

    r = _evaluate(services, "e-after-rotation")
    assert r["decision"] == "deny"
    assert r["reason"] == "signature_quorum_not_met"
    q = r["signature_quorum"]
    assert q["required"] == 2 and q["counted"] == 1 and q["missing"] == 1
    assert q["counted_signers"] == ["bob"]
    rejected = {(x["signed_by"], x["key_id"], x["status"], x["reason"]) for x in q["rejected"]}
    assert rejected == {("alice", "k-alice", "rotated", "signature_key_rotated")}


def test_02_only_old_key_signatures_cannot_pass_after_full_rotation(services):
    """业务2: 两把密钥都轮换后，制品只剩旧钥签名 -> counted=0，绝不放行；
    签名记录本身仍在（不是 missing）。"""
    _quorum_policy(services, 2)
    alice = _make_signer(services, "alice", "k-alice")
    bob = _make_signer(services, "bob", "k-bob")
    _sign(services, alice, "k-alice", "s-alice")
    _sign(services, bob, "k-bob", "s-bob")

    services["keys"].rotate(ADMIN, "k-alice")
    services["keys"].rotate(ADMIN, "k-bob")

    r = _evaluate(services, "e-all-rotated")
    assert r["decision"] == "deny"
    assert r["reason"] == "signature_quorum_not_met"
    q = r["signature_quorum"]
    assert q["required"] == 2 and q["counted"] == 0 and q["missing"] == 2
    assert len(q["rejected"]) == 2
    assert {x["status"] for x in q["rejected"]} == {"rotated"}
    # 记录仍在：不是"一条签名都没有"
    assert r["signature_status"] != "missing"


def _rotate_and_grant(services, old_key: str, signer_id: str) -> str:
    """Rotate ``old_key`` and let the same signer use the replacement key."""
    new_key = services["keys"].rotate(ADMIN, old_key)["active_key"]["key_id"]
    services["keys"].grant_signer(ADMIN, new_key, signer_id)
    return new_key


def test_03_resign_with_active_key_after_rotation_meets_quorum_exactly(services):
    """业务3+4a: 轮换后用当前活跃密钥补签，门槛刚好重新凑齐 -> pass。"""
    _quorum_policy(services, 2)
    alice = _make_signer(services, "alice", "k-alice")
    bob = _make_signer(services, "bob", "k-bob")
    _sign(services, alice, "k-alice", "s-alice")
    _sign(services, bob, "k-bob", "s-bob")

    alice_new_key = _rotate_and_grant(services, "k-alice", "alice")
    bob_new_key = _rotate_and_grant(services, "k-bob", "bob")

    # 还没补签：0 个算数。
    assert _evaluate(services, "e-broken")["signature_quorum"]["counted"] == 0

    # 只补一个：差一票。
    alice_new = Caller(id="alice", roles=("signer", "deployer"), key_grants=(alice_new_key,))
    _sign(services, alice_new, alice_new_key, "s-alice-new")
    r_short = _evaluate(services, "e-one-short")
    assert r_short["decision"] == "deny"
    assert r_short["reason"] == "signature_quorum_not_met"
    q = r_short["signature_quorum"]
    assert q["required"] == 2 and q["counted"] == 1 and q["missing"] == 1

    # 第二个签名方补签：刚好凑齐 -> pass。
    bob_new = Caller(id="bob", roles=("signer", "deployer"), key_grants=(bob_new_key,))
    _sign(services, bob_new, bob_new_key, "s-bob-new")
    r = _evaluate(services, "e-restored")
    assert r["decision"] == "pass" and r["reason"] == "ok"
    q = r["signature_quorum"]
    assert q["required"] == 2 and q["counted"] == 2 and q["missing"] == 0
    assert sorted(q["counted_signers"]) == ["alice", "bob"]
    # 两条旧钥签名仍在 rejected 里逐条可解释，新签名计数。
    assert {x["status"] for x in q["rejected"]} == {"rotated"}


def test_04_one_signature_short_of_threshold_denied_after_rotation(services):
    """业务4b: 三人门槛下轮换一人的钥，其余两人补签、该人未补 -> 差一个不放行。"""
    _quorum_policy(services, 3, request_id="p-rotation-3")
    alice = _make_signer(services, "alice", "k-alice")
    bob = _make_signer(services, "bob", "k-bob")
    carol = _make_signer(services, "carol", "k-carol")
    _sign(services, alice, "k-alice", "s-alice")
    _sign(services, bob, "k-bob", "s-bob")
    _sign(services, carol, "k-carol", "s-carol")
    assert _evaluate(services, "e-before")["decision"] == "pass"

    # Alice 的钥轮换；Bob/Carol 换成自己轮换后的活跃钥并补签，Alice 不补。
    _rotate_and_grant(services, "k-alice", "alice")
    bob_new_key = _rotate_and_grant(services, "k-bob", "bob")
    carol_new_key = _rotate_and_grant(services, "k-carol", "carol")
    _sign(
        services,
        Caller(id="bob", roles=("signer", "deployer"), key_grants=(bob_new_key,)),
        bob_new_key,
        "s-bob-2",
    )
    _sign(
        services,
        Caller(id="carol", roles=("signer", "deployer"), key_grants=(carol_new_key,)),
        carol_new_key,
        "s-carol-2",
    )

    r = _evaluate(services, "e-still-short")
    assert r["decision"] == "deny"
    assert r["reason"] == "signature_quorum_not_met"
    q = r["signature_quorum"]
    assert q["required"] == 3 and q["counted"] == 2 and q["missing"] == 1


def test_05_same_signer_same_key_repeated_submissions_count_once(services):
    """业务5: 轮换后补签时，同一签名方用同一把新钥的重复/重试提交只算一份。"""
    _quorum_policy(services, 2)
    alice = _make_signer(services, "alice", "k-alice")
    bob = _make_signer(services, "bob", "k-bob")
    _sign(services, alice, "k-alice", "s-alice")
    _sign(services, bob, "k-bob", "s-bob")
    new_key = _rotate_and_grant(services, "k-alice", "alice")
    services["keys"].rotate(ADMIN, "k-bob")  # Bob 不补签

    alice_new = Caller(id="alice", roles=("signer", "deployer"), key_grants=(new_key,))
    first = _sign(services, alice_new, new_key, "s-alice-new")

    # 同一 request_id 的重试 -> 原记录，dedup。
    retry = _sign(services, alice_new, new_key, "s-alice-new")
    assert retry["dedup"] is True
    assert retry["signature"] == first["signature"]

    # 换 request_id 的重复提交（甚至连续三次）-> 仍是同一个 slot。
    for rid in ("s-alice-dup-1", "s-alice-dup-2", "s-alice-dup-3"):
        dup = _sign(services, alice_new, new_key, rid)
        assert dup["dedup"] is True
        assert dup["signature"] == first["signature"]

    slots = services["store"].state["signatures"][DIGEST]
    # 仅三个 slot：alice 旧钥、bob 旧钥、alice 新钥。
    assert set(slots) == {"alice#k-alice", "bob#k-bob", f"alice#{new_key}"}

    r = _evaluate(services, "e-dup-count")
    # Alice 无论如何只能占一个席位，Bob 已轮换 -> 差一票。
    assert r["decision"] == "deny"
    q = r["signature_quorum"]
    assert q["counted"] == 1 and q["counted_signers"] == ["alice"]


def test_06_concurrent_and_retry_registration_dedup_is_stable(tmp_path):
    """业务6: 轮换后多个签名方并发补签（各自还带一次重试），每个
    (signer, key) slot 恰好登记一次；结论计数与席位不重不乱。"""
    data_dir = str(tmp_path / "data")
    n = 5

    def fresh_services():
        store = Store(data_dir)
        clock = FixedClock()
        keys = KeyService(store, clock)
        signing = SigningService(store, clock, keys)
        policy = PolicyService(store, clock)
        from admission.engine import AdmissionService

        admission = AdmissionService(store, clock, signing, policy)
        return {
            "store": store,
            "clock": clock,
            "keys": keys,
            "signing": signing,
            "policy": policy,
            "admission": admission,
        }

    svc = fresh_services()
    _quorum_policy(svc, n, request_id="p-conc")
    active_keys = {}
    for i in range(n):
        sid = f"signer-{i}"
        _make_signer(svc, sid, f"k{i}")
        caller = Caller(id=sid, roles=("signer",), key_grants=(f"k{i}",))
        _sign(svc, caller, f"k{i}", f"s-{i}-old")
        # 全部轮换并重新授权。
        active_keys[sid] = _rotate_and_grant(svc, f"k{i}", sid)

    # 并发补签：每个签名方在两个线程里用不同 request_id 抢同一个 slot，
    # 另用同 request_id 模拟一次重试。
    def worker(i):
        s = fresh_services()
        sid = f"signer-{i}"
        key = active_keys[sid]
        caller = Caller(id=sid, roles=("signer",), key_grants=(key,))
        attempts = [f"s-{i}-new-a", f"s-{i}-new-b", f"s-{i}-new-a"]
        out = []
        for rid in attempts:
            out.append(
                s["signing"].sign_artifact(
                    caller,
                    artifact_digest=DIGEST,
                    artifact_type=TYPE,
                    key_id=key,
                    request_id=rid,
                    signature_ttl=None,
                )
            )
        return out

    with ThreadPoolExecutor(max_workers=n * 2) as pool:
        results = list(pool.map(worker, range(n)))

    after = fresh_services()
    slots = after["store"].state["signatures"][DIGEST]
    # n 条旧钥签名 + n 条新钥签名，每个 slot 恰好一份。
    new_slots = {f"signer-{i}#{active_keys[f'signer-{i}']}" for i in range(n)}
    old_slots = {f"signer-{i}#k{i}" for i in range(n)}
    assert set(slots) == new_slots | old_slots
    for outs in results:
        sigs = {o["signature"] for o in outs}
        assert len(sigs) == 1  # 三次尝试拿到的是同一条记录

    r = after["admission"].evaluate(
        DEPLOYER, artifact_digest=DIGEST, artifact_type=TYPE, request_id="e-conc-final"
    )
    assert r["decision"] == "pass"
    q = r["signature_quorum"]
    assert q["required"] == n and q["counted"] == n and q["missing"] == 0
    assert sorted(q["counted_signers"]) == [f"signer-{i}" for i in range(n)]
    # 恰好 n 条旧钥签名被标记为 rotated，没有 duplicate_* 噪声。
    assert len(q["rejected"]) == n
    assert {x["status"] for x in q["rejected"]} == {"rotated"}


def test_07_old_records_remain_queryable_and_recorded_verdicts_replay(services):
    """业务7: 轮换+补签后，旧钥历史签名仍可逐条查询，且不会和新签名冲突；
    事实变化前已记录的判定（pass 与 deny 各一）按 request_id 重放保持原样。"""
    _quorum_policy(services, 2)
    alice = _make_signer(services, "alice", "k-alice")
    bob = _make_signer(services, "bob", "k-bob")
    _sign(services, alice, "k-alice", "s-alice")
    _sign(services, bob, "k-bob", "s-bob")
    _evaluate(services, "e-recorded-pass")

    new_key = _rotate_and_grant(services, "k-alice", "alice")
    _evaluate(services, "e-recorded-deny")  # 轮换后、补签前记录的 deny

    alice_new = Caller(id="alice", roles=("signer", "deployer"), key_grants=(new_key,))
    _sign(services, alice_new, new_key, "s-alice-new")
    assert _evaluate(services, "e-now-pass")["decision"] == "pass"

    # 历史签名全部保留可查（含已轮换的旧钥记录）。
    listed = services["signing"].get_signatures(DIGEST)["signatures"]
    by_key = {s["key_id"]: s["signed_by"] for s in listed}
    assert by_key.get("k-alice") == "alice"
    assert by_key.get(new_key) == "alice"
    assert by_key.get("k-bob") == "bob"

    # 同一 request_id 再评估 -> 回放首次结论，而不是按当前事实重算。
    again_deny = _evaluate(services, "e-recorded-deny")
    assert again_deny["dedup"] is True
    assert again_deny["decision"] == "deny"
    again_pass = _evaluate(services, "e-recorded-pass")
    assert again_pass["dedup"] is True
    assert again_pass["decision"] == "pass"

    # replay 接口逐字复现，旧 deny 不被后来补签的事实改写。
    replay_deny = services["admission"].replay("e-recorded-deny")
    assert replay_deny["result"]["decision"] == "deny"
    assert replay_deny["result"]["reason"] == "signature_quorum_not_met"
    assert replay_deny["result"]["signature_quorum"]["counted"] == 1
    replay_pass = services["admission"].replay("e-recorded-pass")
    assert replay_pass["result"]["decision"] == "pass"


def test_08_legacy_require_signature_policy_rotation_semantics(services):
    """业务8: 旧的 require_signature（门槛1）策略下，轮换后旧钥签名按具体
    签名原因拒绝（signature_key_rotated，而非 quorum 码）；用活跃新钥补签
    后恢复放行——旧策略语义不回归。"""
    services["policy"].create_version(
        ADMIN,
        [
            PolicyRule(
                id="images",
                action=Decision.PASS,
                match_types=(TYPE,),
                require_signature=True,
                roles_allowed=("deployer",),
            )
        ],
        request_id="p-legacy",
        expected_version=0,
    )
    ci = _make_signer(services, "ci", "k-ci")
    _sign(services, ci, "k-ci", "s-ci")
    assert _evaluate(services, "e-legacy-pass")["decision"] == "pass"

    services["keys"].rotate(ADMIN, "k-ci")
    r = _evaluate(services, "e-legacy-rotated")
    assert r["decision"] == "deny"
    assert r["reason"] == "signature_key_rotated"
    assert r["signature_status"] == "rotated"

    new_key = services["store"].state["keys"]["k-ci"]["rotated_to"]
    services["keys"].grant_signer(ADMIN, new_key, "ci")
    ci_new = Caller(id="ci", roles=("signer", "deployer"), key_grants=(new_key,))
    _sign(services, ci_new, new_key, "s-ci-new")
    r2 = _evaluate(services, "e-legacy-resigned")
    assert r2["decision"] == "pass" and r2["reason"] == "ok"
    assert r2["signature_quorum"]["required"] == 1


def test_09_evaluation_log_mentions_business_identifiers(services, caplog):
    """运行日志要能看出覆盖的业务：评估日志含制品摘要、quorum=counted/required、
    decision，且 rejected 的每条原因出现在 basis 中。"""
    _quorum_policy(services, 2)
    alice = _make_signer(services, "alice", "k-alice")
    _sign(services, alice, "k-alice", "s-alice")
    services["keys"].rotate(ADMIN, "k-alice")

    with caplog.at_level(logging.INFO, logger="admission.engine"):
        r = _evaluate(services, "e-log-rotation")
    assert r["reason"] == "signature_quorum_not_met"
    text = "\n".join(rec.getMessage() for rec in caplog.records)
    assert DIGEST in text
    assert "quorum=0/2" in text
    assert "decision=deny" in text
    # basis 给出每条未计数签名的状态，账本给出对应的稳定原因码。
    assert "alice#k-alice -> rotated" in "\n".join(r["basis"])
    assert r["signature_quorum"]["rejected"][0]["reason"] == "signature_key_rotated"
