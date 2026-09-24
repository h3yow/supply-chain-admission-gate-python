"""Policy version management.

* Every change is a new immutable version (append-only); the current pointer
  moves forward only, including rollback (a rollback appends a new version
  whose rules equal the target version's rules — old versions are never
  rewritten, so history stays reproducible).
* ``expected_version`` provides optimistic concurrency control: concurrent
  writers cannot silently overwrite each other.
* Rules are stored ordered; the first rule matching an artifact type wins.
"""
from __future__ import annotations

from admission.clock import Clock, utcnow_str
from admission.models import (
    Caller,
    Decision,
    PolicyNotFoundError,
    PolicyRule,
    PolicyVersion,
    PolicyVersionConflictError,
    to_plain,
)
from admission.storage import Store

POLICY_ADMIN_ROLE = "policy_admin"


class PolicyService:
    def __init__(self, store: Store, clock: Clock) -> None:
        self.store = store
        self.clock = clock

    # -------------------------------------------------------------- helpers
    def _require_policy_admin(self, caller: Caller, action: str) -> None:
        from admission.keys import PermissionDeniedError

        if not caller.has_role(POLICY_ADMIN_ROLE):
            raise PermissionDeniedError(
                f"caller '{caller.id}' lacks role '{POLICY_ADMIN_ROLE}' required to {action}",
                details={"caller": caller.summary(), "required_role": POLICY_ADMIN_ROLE},
            )

    def _hydrate(self, data: dict) -> PolicyVersion:
        rules = []
        for r in data["rules"]:
            r = dict(r)
            r["action"] = Decision(r["action"])  # stored as its string value
            rules.append(PolicyRule(**r))
        return PolicyVersion(
            version=data["version"],
            rules=tuple(rules),
            created_at=data["created_at"],
            created_by=data["created_by"],
            comment=data.get("comment", ""),
        )

    def current_version(self) -> PolicyVersion:
        v = self.store.state["current_policy_version"]
        return self.get_version(v)

    def get_version(self, version: int) -> PolicyVersion:
        data = self.store.state["policies"].get(str(version))
        if data is None:
            raise PolicyNotFoundError(
                f"policy version {version} does not exist",
                details={"version": version},
            )
        return self._hydrate(data)

    def list_versions(self) -> list[dict]:
        items = sorted(self.store.state["policies"].values(),
                       key=lambda p: p["version"])
        return [
            {
                "version": p["version"],
                "created_at": p["created_at"],
                "created_by": p["created_by"],
                "comment": p.get("comment", ""),
                "rule_ids": [r["id"] for r in p["rules"]],
            }
            for p in items
        ]

    # ------------------------------------------------------------ mutations
    def create_version(
        self,
        caller: Caller,
        rules: list[PolicyRule] | tuple[PolicyRule, ...],
        *,
        comment: str = "",
        expected_version: int | None = None,
        request_id: str | None = None,
    ) -> dict:
        self._require_policy_admin(caller, "create policy versions")
        self._validate_rules(rules)
        now = utcnow_str(self.clock)
        request_id = request_id or f"policy-create-{now}-{caller.id}"

        with self.store.transaction() as state:
            current = state["current_policy_version"]
            if expected_version is not None and expected_version != current:
                raise PolicyVersionConflictError(
                    f"expected current version {expected_version} but it is {current}",
                    details={"expected": expected_version, "actual": current},
                )
            if request_id in state["request_index"]:
                idx = state["request_index"][request_id]
                if idx["kind"] in ("policy", "policy_rollback"):
                    return self._hydrate(state["policies"][idx["result_key"]]).summary()
                raise PolicyVersionConflictError(
                    f"request_id '{request_id}' already used for a non-policy request",
                    details={"request_id": request_id},
                )
            version = current + 1
            record = PolicyVersion(
                version=version,
                rules=tuple(rules),
                created_at=now,
                created_by=caller.id,
                comment=comment,
            )
            self.store.emit(state, {
                "event_type": "policy_created",
                "occurred_at": now,
                "actor": caller.id,
                "request_id": request_id,
                "payload": {"policy": to_plain(record)},
            })
            return record.summary()

    def rollback(
        self,
        caller: Caller,
        target_version: int,
        comment: str = "",
        request_id: str | None = None,
    ) -> dict:
        self._require_policy_admin(caller, "roll back policy")
        now = utcnow_str(self.clock)
        request_id = request_id or f"policy-rollback-{target_version}-{now}-{caller.id}"
        with self.store.transaction() as state:
            target_data = state["policies"].get(str(target_version))
            if target_data is None:
                raise PolicyNotFoundError(
                    f"cannot roll back to unknown version {target_version}",
                    details={"version": target_version},
                )
            if request_id in state["request_index"]:
                idx = state["request_index"][request_id]
                if idx["kind"] in ("policy", "policy_rollback"):
                    return self._hydrate(state["policies"][idx["result_key"]]).summary()
                raise PolicyVersionConflictError(
                    f"request_id '{request_id}' already used",
                    details={"request_id": request_id},
                )
            new_version = state["current_policy_version"] + 1
            record = PolicyVersion(
                version=new_version,
                rules=tuple(PolicyRule(**r) for r in target_data["rules"]),
                created_at=now,
                created_by=caller.id,
                comment=comment or f"rollback to v{target_version}",
            )
            self.store.emit(state, {
                "event_type": "policy_rolled_back",
                "occurred_at": now,
                "actor": caller.id,
                "request_id": request_id,
                "payload": {
                    "new_policy": to_plain(record),
                    "source_version": target_version,
                },
            })
            return record.summary()

    @staticmethod
    def _validate_rules(rules) -> None:
        seen: set[str] = set()
        for rule in rules:
            if rule.action not in tuple(Decision):
                raise ValueError(f"rule '{rule.id}' has invalid action {rule.action!r}")
            if rule.id in seen:
                raise ValueError(f"duplicate rule id '{rule.id}'")
            seen.add(rule.id)
