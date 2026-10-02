"""Deterministic admission evaluation plus its service orchestration.

``select_rule`` / ``evaluate`` are pure functions: the same caller, artifact,
pinned policy version and fact snapshot always produce byte-identical results.
``AdmissionService`` pins the policy version, reads the current signature
facts, deduplicates repeated evaluations by ``request_id`` and persists every
conclusion in the audit log so it can be replayed verbatim later.

Fixed decision order (the first failing gate decides ``reason``):

1. identity must be known
2. a policy version must exist and contain a rule matching the artifact type
   (otherwise ``policy_not_covered`` -> manual review)
3. the caller must hold a role allowed by the matched rule
4. if the rule requires signatures (``require_signature`` or
   ``min_signatures``), enough *distinct* signers must hold currently-valid
   signatures: the same signer or the same key never counts twice
5. the rule action gives pass / deny / manual_review
"""
from __future__ import annotations

import logging

from admission.clock import Clock, utcnow_str
from admission.models import (
    ArtifactManifest,
    Caller,
    Decision,
    DenyReason,
    EvaluationResult,
    IdempotencyConflictError,
    PolicyRule,
    PolicyVersion,
)
from admission.policy import PolicyService
from admission.signing import SigningService
from admission.storage import Store

logger = logging.getLogger("admission.engine")


def select_rule(policy: PolicyVersion | None, artifact_type: str) -> PolicyRule | None:
    if policy is None:
        return None
    for rule in policy.rules:
        if rule.matches(artifact_type):
            return rule
    return None


def account_quorum(signatures: list[dict], required: int) -> dict:
    """Count distinct currently-valid signers towards ``required``.

    A signature counts only when it is ``valid`` *and* neither its signer nor
    its key has already counted — the same person or the same key can never
    fill two seats. Every registered signature that does not count is listed
    under ``rejected`` with the reason (its invalid status, or the duplicate
    contributor it collides with). Input order must be deterministic (the
    signing service sorts), which makes the accounting deterministic.
    """
    counted_signers: list[str] = []
    counted_keys: list[str] = []
    rejected: list[dict] = []
    for entry in signatures:
        sig = entry["signature"]
        signer, key_id = sig["signed_by"], sig["key_id"]
        if entry["status"] != "valid":
            rejected.append({"signed_by": signer, "key_id": key_id,
                             "status": entry["status"], "reason": entry["reason"]})
        elif signer in counted_signers:
            rejected.append({"signed_by": signer, "key_id": key_id,
                             "status": "duplicate_signer",
                             "reason": "signature_duplicate_signer"})
        elif key_id in counted_keys:
            rejected.append({"signed_by": signer, "key_id": key_id,
                             "status": "duplicate_key",
                             "reason": "signature_duplicate_key"})
        else:
            counted_signers.append(signer)
            counted_keys.append(key_id)
    counted = len(counted_signers)
    return {
        "required": required,
        "counted": counted,
        "missing": max(0, required - counted),
        "counted_signers": counted_signers,
        "counted_keys": counted_keys,
        "rejected": rejected,
    }


def evaluate(
    *,
    caller: Caller | None,
    artifact: ArtifactManifest,
    policy: PolicyVersion | None,
    signatures: list[dict],
    evaluated_at: str,
    request_id: str,
) -> EvaluationResult:
    # Representative signature for the legacy single-signature fields: the
    # first valid one if any, else the first registered, else nothing.
    representative = next((e for e in signatures if e["status"] == "valid"),
                          signatures[0] if signatures else None)
    signature = representative["signature"] if representative else None
    signature_status = representative["status"] if representative else "missing"
    signature_reason = representative["reason"] if representative \
        else DenyReason.SIGNATURE_MISSING.value

    basis: list[str] = [
        f"request_id={request_id}",
        f"evaluated_at={evaluated_at}",
        f"artifact={artifact.digest} type={artifact.artifact_type}",
        f"policy_version={policy.version if policy else 0}",
    ]
    quorum: dict | None = None

    def result(decision: Decision, reason: str, rule: PolicyRule | None,
               rationale: str) -> EvaluationResult:
        res = EvaluationResult(
            decision=decision,
            reason=reason,
            policy_version=policy.version if policy else 0,
            rule_id=rule.id if rule else None,
            evaluated_at=evaluated_at,
            request_id=request_id,
            caller=caller.summary() if caller else {"id": None},
            artifact=artifact.summary(),
            signature=signature,
            signature_status=signature_status,
            rationale=rationale,
            basis=basis,
            signature_quorum=quorum,
        )
        logger.info(
            "admission input=%s decision=%s reason=%s basis=%s",
            " ".join(
                f"{k}={v}" for k, v in {
                    "request_id": request_id,
                    "caller": caller.id if caller else None,
                    "artifact": artifact.digest,
                    "policy_version": res.policy_version,
                    "signature_status": signature_status,
                    "quorum": (f"{quorum['counted']}/{quorum['required']}"
                               if quorum else "n/a"),
                }.items()
            ),
            decision.value, reason, basis,
        )
        return res

    # Gate 1: identity
    if caller is None:
        basis.append("gate1: identity missing")
        return result(Decision.DENY, DenyReason.IDENTITY_UNKNOWN.value, None,
                      "request has no authenticated caller identity")
    basis.append(f"gate1: identity='{caller.id}' roles={list(caller.roles)}")

    # Gate 2: coverage
    rule = select_rule(policy, artifact.artifact_type)
    if policy is None:
        basis.append("gate2: no policy version exists yet")
        return result(Decision.MANUAL_REVIEW, DenyReason.POLICY_NOT_COVERED.value, None,
                      "no policy has been published; human review required")
    if rule is None:
        covered = [r.id for r in policy.rules]
        basis.append(f"gate2: no rule matches type '{artifact.artifact_type}'; rules={covered}")
        return result(Decision.MANUAL_REVIEW, DenyReason.POLICY_NOT_COVERED.value, None,
                      f"policy v{policy.version} has no rule covering "
                      f"artifact type '{artifact.artifact_type}'")
    basis.append(f"gate2: matched rule '{rule.id}' action={rule.action.value} "
                 f"match_types={list(rule.match_types) or ['*']}")

    # Gate 3: role permission
    if rule.roles_allowed and not caller.has_role_any(rule.roles_allowed):
        basis.append(f"gate3: caller lacks required role(s) {list(rule.roles_allowed)}")
        return result(Decision.DENY, DenyReason.PERMISSION_DENIED.value, rule,
                      f"rule '{rule.id}' requires one of {list(rule.roles_allowed)}; "
                      f"caller has {list(caller.roles)}")
    basis.append(
        f"gate3: role check passed ({list(rule.roles_allowed) or 'any authenticated'})")

    # Gate 4: signature quorum
    required = rule.required_signatures
    if required > 0:
        quorum = account_quorum(signatures, required)
        basis.append(
            f"gate4: signatures required={required} "
            f"counted={quorum['counted']} missing={quorum['missing']} "
            f"registered={len(signatures)}")
        for rej in quorum["rejected"]:
            basis.append(
                f"gate4: not counted {rej['signed_by']}#{rej['key_id']} "
                f"-> {rej['status']}")
        if not signatures:
            return result(
                Decision.DENY, DenyReason.SIGNATURE_MISSING.value, rule,
                f"rule '{rule.id}' requires a valid signature "
                f"({required} distinct valid signer(s)); none is registered "
                f"for this artifact",
            )
        if quorum["counted"] < required:
            # Legacy single-signature rules keep their specific per-signature
            # reason (expired/revoked/...); multi-signature rules report the
            # quorum shortfall as its own distinguishable reason.
            reason = (signature_reason if required == 1
                      else DenyReason.SIGNATURE_QUORUM_NOT_MET.value)
            return result(
                Decision.DENY, reason, rule,
                f"rule '{rule.id}' requires {required} distinct valid "
                f"signer(s); only {quorum['counted']} count "
                f"(missing {quorum['missing']})",
            )
    elif rule.require_signature:
        # Unreachable: require_signature implies required >= 1.
        raise AssertionError("require_signature must yield required >= 1")
    elif signatures:
        basis.append(f"gate4: signature not required; observed status "
                     f"'{signature_status}'")
    else:
        basis.append("gate4: signature not required; none registered")

    # Gate 5: action
    if rule.action is Decision.PASS:
        return result(Decision.PASS, "ok", rule,
                      f"rule '{rule.id}' explicitly allows this artifact")
    if rule.action is Decision.MANUAL_REVIEW:
        return result(Decision.MANUAL_REVIEW, "ok", rule,
                      f"rule '{rule.id}' routes this artifact to manual review")
    return result(Decision.DENY, DenyReason.POLICY_EXPLICIT_DENY.value, rule,
                  f"rule '{rule.id}' explicitly denies this artifact")


class AdmissionService:
    def __init__(self, store: Store, clock: Clock,
                 signing: SigningService, policy: PolicyService) -> None:
        self.store = store
        self.clock = clock
        self.signing = signing
        self.policy = policy

    def _load_policy(self, version: int | None) -> PolicyVersion | None:
        target = version
        if target is None:
            target = self.store.state["current_policy_version"]
        if not target:
            return None
        return self.policy.get_version(target)

    def evaluate(
        self,
        caller: Caller | None,
        *,
        artifact_digest: str,
        artifact_type: str,
        size: int = 0,
        request_id: str,
        policy_version: int | None = None,
    ) -> dict:
        artifact = ArtifactManifest(digest=artifact_digest,
                                    artifact_type=artifact_type, size=size)
        with self.store.transaction() as state:
            # Deduplicated evaluation: same request_id reproduces the stored
            # conclusion exactly, regardless of what changed afterwards.
            idx = state["request_index"].get(request_id)
            if idx is not None and idx["kind"] == "evaluate":
                if idx["result_key"] != artifact_digest:
                    raise IdempotencyConflictError(
                        f"request_id '{request_id}' was already evaluated for a "
                        f"different artifact '{idx['result_key']}'",
                        details={"request_id": request_id,
                                 "original_artifact": idx["result_key"],
                                 "artifact_digest": artifact_digest},
                    )
                for event in reversed(self.store.read_audit()):
                    if (event.get("request_id") == request_id
                            and event["event_type"] == "admission_evaluated"):
                        return event["payload"]["result"] | {"dedup": True}
                raise AssertionError("index points to missing evaluation event")

            policy = self._load_policy(policy_version)
            signatures = self.signing.validate_signatures(
                artifact_digest, artifact_type)
            evaluated_at = utcnow_str(self.clock)
            res = evaluate(
                caller=caller,
                artifact=artifact,
                policy=policy,
                signatures=signatures,
                evaluated_at=evaluated_at,
                request_id=request_id,
            )
            result_dict = res.to_dict()
            self.store.emit(state, {
                "event_type": "admission_evaluated",
                "occurred_at": evaluated_at,
                "actor": caller.id if caller else "anonymous",
                "request_id": request_id,
                "payload": {
                    "artifact_digest": artifact_digest,
                    "artifact_type": artifact_type,
                    "size": size,
                    "requested_policy_version": policy_version,
                    "result": result_dict,
                },
            })
            return result_dict | {"dedup": False}

    def replay(self, request_id: str) -> dict:
        """Reproduce a historical conclusion verbatim from the audit log."""
        for event in self.store.read_audit():
            if (event.get("request_id") == request_id
                    and event["event_type"] == "admission_evaluated"):
                return {
                    "replayed": True,
                    "recorded_seq": event["seq"],
                    "recorded_at": event["occurred_at"],
                    "request_id": request_id,
                    "result": event["payload"]["result"],
                }
        from admission.models import NothingToReplayError

        raise NothingToReplayError(
            f"no recorded evaluation found for request_id '{request_id}'",
            details={"request_id": request_id},
        )
