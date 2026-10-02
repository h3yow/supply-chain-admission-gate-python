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
4. if the rule requires signatures, at least ``rule.min_signatures``
   signatures from distinct signing parties (and distinct keys) must be
   currently valid
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


def evaluate(
    *,
    caller: Caller | None,
    artifact: ArtifactManifest,
    policy: PolicyVersion | None,
    signature_report: dict,
    evaluated_at: str,
    request_id: str,
) -> EvaluationResult:
    signature = signature_report["signature"]
    signature_status = signature_report["status"]
    signature_reason = signature_report["reason"]
    basis: list[str] = [
        f"request_id={request_id}",
        f"evaluated_at={evaluated_at}",
        f"artifact={artifact.digest} type={artifact.artifact_type}",
        f"policy_version={policy.version if policy else 0}",
    ]

    def result(decision: Decision, reason: str, rule: PolicyRule | None,
               rationale: str) -> EvaluationResult:
        report = signature_report if (rule and rule.require_signature) else None
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
            signature_report=report,
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
    basis.append(f"gate4: signature_required={rule.require_signature} "
                 f"required={rule.min_signatures} "
                 f"counted={signature_report['counted']} "
                 f"status={signature_status or 'n/a'}")
    if rule.require_signature:
        for entry in signature_report["entries"]:
            sig = entry["signature"]
            basis.append(
                f"gate4: signature by='{sig['signed_by']}' key='{sig['key_id']}' "
                f"status={entry['status']} counted={entry['counted']}"
                + (f" not_counted_reason={entry['not_counted_reason']}"
                   if entry["not_counted_reason"] else ""))
        if signature_status != "valid":
            if rule.min_signatures == 1:
                rationale = (f"rule '{rule.id}' requires a valid signature; "
                             f"status is '{signature_status or 'missing'}'")
            else:
                rationale = (
                    f"rule '{rule.id}' requires {rule.min_signatures} valid "
                    f"distinct-signer signatures; counted "
                    f"{signature_report['counted']} (status "
                    f"'{signature_status or 'missing'}', missing "
                    f"{signature_report['missing']})")
            return result(Decision.DENY,
                          signature_reason or DenyReason.SIGNATURE_MISSING.value,
                          rule, rationale)
    elif signature_status is not None:
        basis.append(f"gate4: signature not required; observed status "
                     f"'{signature_status}'")

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
            rule = select_rule(policy, artifact.artifact_type)
            required = rule.min_signatures if (
                rule is not None and rule.require_signature) else 1
            sig_report = self.signing.evaluate_signatures(
                artifact_digest, artifact_type, required=required)
            evaluated_at = utcnow_str(self.clock)
            res = evaluate(
                caller=caller,
                artifact=artifact,
                policy=policy,
                signature_report=sig_report,
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
