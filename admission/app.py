"""FastAPI application: local HTTP surface for the admission gate.

Caller identity is simulated (there is no real IdP locally) via headers:

* ``X-Caller-Id``            required on mutating/evaluation routes
* ``X-Caller-Roles``         comma-separated roles, e.g. "signer,deployer"
* ``X-Caller-Key-Grants``    comma-separated key ids the caller may use

Authorization is still enforced server-side against the key-grant registry;
the headers only carry identity claims.
"""
from __future__ import annotations

import os
from datetime import timedelta
from functools import cache
from typing import Any

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from admission.audit import AuditService
from admission.clock import SystemClock
from admission.engine import AdmissionService
from admission.keys import KeyService
from admission.models import (
    AdmissionError,
    Caller,
    CallerRequiredError,
    Decision,
    PolicyRule,
)
from admission.policy import PolicyService
from admission.signing import SigningService
from admission.storage import Store


# --------------------------------------------------------------------- wiring
def _data_dir() -> str:
    return os.environ.get("ADMISSION_DATA_DIR", ".admission-data")


@cache
def get_services(data_dir: str | None = None) -> dict[str, Any]:
    store = Store(data_dir or _data_dir())
    clock = SystemClock()
    keys = KeyService(store, clock)
    signing = SigningService(store, clock, keys)
    policy = PolicyService(store, clock)
    audit = AuditService(store)
    admission = AdmissionService(store, clock, signing, policy)
    return {"store": store, "clock": clock, "keys": keys, "signing": signing,
            "policy": policy, "audit": audit, "admission": admission}


def reset_services() -> None:
    """Drop cached singletons (used by tests that point at a temp directory)."""
    get_services.cache_clear()


# --------------------------------------------------------------------- schemas
def _caller(
    x_caller_id: str | None,
    x_caller_roles: str | None,
    x_caller_key_grants: str | None,
    *,
    required: bool = True,
) -> Caller | None:
    if not x_caller_id:
        if required:
            raise CallerRequiredError(
                "missing X-Caller-Id header; caller identity is required",
                details={"required_header": "X-Caller-Id"},
            )
        return None

    def split(value: str | None) -> tuple[str, ...]:
        return tuple(v.strip() for v in (value or "").split(",") if v.strip())

    return Caller(
        id=x_caller_id.strip(),
        roles=split(x_caller_roles),
        key_grants=split(x_caller_key_grants),
    )


class RuleIn(BaseModel):
    id: str
    action: Decision
    match_types: list[str] = Field(default_factory=list)
    require_signature: bool = False
    roles_allowed: list[str] = Field(default_factory=list)
    min_signatures: int = 0  # >0: distinct valid signers required (implies require_signature)


class PolicyIn(BaseModel):
    rules: list[RuleIn]
    comment: str = ""
    expected_version: int | None = None
    request_id: str | None = None


class RollbackIn(BaseModel):
    target_version: int
    comment: str = ""
    request_id: str | None = None


class KeyIn(BaseModel):
    key_id: str | None = None
    ttl_days: int | None = 90


class GrantIn(BaseModel):
    signer_id: str


class SignIn(BaseModel):
    artifact_digest: str
    artifact_type: str
    key_id: str
    request_id: str
    ttl_days: int | None = 30


class EvaluateIn(BaseModel):
    artifact_digest: str
    artifact_type: str
    size: int = 0
    request_id: str
    policy_version: int | None = None


# ------------------------------------------------------------------------ app
def create_app() -> FastAPI:
    app = FastAPI(title="Supply-Chain Admission Gate (local)", version="0.1.0")

    @app.exception_handler(AdmissionError)
    async def _admission_error_handler(_request, exc: AdmissionError):
        return JSONResponse(status_code=exc.http_status, content=exc.to_dict())

    @app.exception_handler(ValueError)
    async def _value_error_handler(_request, exc: ValueError):
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=400,
            content={"error": "invalid_payload", "message": str(exc), "details": {}},
        )

    @app.get("/health")
    def health() -> dict:
        svc = get_services()
        return {"status": "ok",
                "current_policy_version": svc["store"].state["current_policy_version"],
                "audit_events": svc["audit"].last_seq()}

    # ------------------------------------------------------------- keys
    @app.post("/admin/keys")
    def generate_key(body: KeyIn,
                     x_caller_id: str | None = Header(default=None),
                     x_caller_roles: str | None = Header(default=None),
                     x_caller_key_grants: str | None = Header(default=None)):
        svc = get_services()
        caller = _caller(x_caller_id, x_caller_roles, x_caller_key_grants)
        ttl = None if body.ttl_days is None else timedelta(days=body.ttl_days)
        return svc["keys"].generate(caller, key_id=body.key_id, ttl=ttl)

    @app.get("/admin/keys")
    def list_keys():
        return {"keys": get_services()["keys"].list_keys(),
                "grants": get_services()["keys"].list_grants()}

    @app.post("/admin/keys/{key_id}/rotate")
    def rotate_key(key_id: str,
                   x_caller_id: str | None = Header(default=None),
                   x_caller_roles: str | None = Header(default=None),
                   x_caller_key_grants: str | None = Header(default=None)):
        svc = get_services()
        caller = _caller(x_caller_id, x_caller_roles, x_caller_key_grants)
        return svc["keys"].rotate(caller, key_id)

    @app.post("/admin/keys/{key_id}/revoke")
    def revoke_key(key_id: str, body: dict | None = None,
                   x_caller_id: str | None = Header(default=None),
                   x_caller_roles: str | None = Header(default=None),
                   x_caller_key_grants: str | None = Header(default=None)):
        svc = get_services()
        caller = _caller(x_caller_id, x_caller_roles, x_caller_key_grants)
        reason = (body or {}).get("reason", "")
        return svc["keys"].revoke(caller, key_id, reason)

    @app.post("/admin/keys/{key_id}/grants")
    def grant(key_id: str, body: GrantIn,
              x_caller_id: str | None = Header(default=None),
              x_caller_roles: str | None = Header(default=None),
              x_caller_key_grants: str | None = Header(default=None)):
        svc = get_services()
        caller = _caller(x_caller_id, x_caller_roles, x_caller_key_grants)
        return svc["keys"].grant_signer(caller, key_id, body.signer_id)

    @app.delete("/admin/keys/{key_id}/grants/{signer_id}")
    def revoke_grant(key_id: str, signer_id: str,
                     x_caller_id: str | None = Header(default=None),
                     x_caller_roles: str | None = Header(default=None),
                     x_caller_key_grants: str | None = Header(default=None)):
        svc = get_services()
        caller = _caller(x_caller_id, x_caller_roles, x_caller_key_grants)
        return svc["keys"].revoke_signer_grant(caller, key_id, signer_id)

    # ---------------------------------------------------------- signing
    @app.post("/signatures")
    def sign_artifact(body: SignIn,
                      x_caller_id: str | None = Header(default=None),
                      x_caller_roles: str | None = Header(default=None),
                      x_caller_key_grants: str | None = Header(default=None)):
        svc = get_services()
        caller = _caller(x_caller_id, x_caller_roles, x_caller_key_grants)
        ttl = None if body.ttl_days is None else timedelta(days=body.ttl_days)
        return svc["signing"].sign_artifact(
            caller,
            artifact_digest=body.artifact_digest,
            artifact_type=body.artifact_type,
            key_id=body.key_id,
            request_id=body.request_id,
            signature_ttl=ttl,
        )

    @app.get("/signatures/{artifact_digest:path}")
    def get_signatures(artifact_digest: str):
        return get_services()["signing"].get_signatures(artifact_digest)

    # ---------------------------------------------------------- policies
    @app.post("/admin/policies")
    def create_policy(body: PolicyIn,
                      x_caller_id: str | None = Header(default=None),
                      x_caller_roles: str | None = Header(default=None),
                      x_caller_key_grants: str | None = Header(default=None)):
        svc = get_services()
        caller = _caller(x_caller_id, x_caller_roles, x_caller_key_grants)
        rules = [
            PolicyRule(id=r.id, action=r.action,
                       match_types=tuple(r.match_types),
                       require_signature=r.require_signature,
                       roles_allowed=tuple(r.roles_allowed),
                       min_signatures=r.min_signatures)
            for r in body.rules
        ]
        return svc["policy"].create_version(
            caller, rules, comment=body.comment,
            expected_version=body.expected_version, request_id=body.request_id)

    @app.post("/admin/policies/rollback")
    def rollback_policy(body: RollbackIn,
                        x_caller_id: str | None = Header(default=None),
                        x_caller_roles: str | None = Header(default=None),
                        x_caller_key_grants: str | None = Header(default=None)):
        svc = get_services()
        caller = _caller(x_caller_id, x_caller_roles, x_caller_key_grants)
        return svc["policy"].rollback(
            caller, body.target_version, comment=body.comment, request_id=body.request_id)

    @app.get("/admin/policies")
    def list_policies():
        return {"versions": get_services()["policy"].list_versions()}

    @app.get("/admin/policies/{version}")
    def get_policy(version: int):
        from admission.models import to_plain

        return to_plain(get_services()["policy"].get_version(version))

    # --------------------------------------------------------- admission
    @app.post("/admission/evaluate")
    def evaluate(body: EvaluateIn,
                 x_caller_id: str | None = Header(default=None),
                 x_caller_roles: str | None = Header(default=None),
                 x_caller_key_grants: str | None = Header(default=None)):
        svc = get_services()
        caller = _caller(x_caller_id, x_caller_roles, x_caller_key_grants, required=False)
        return svc["admission"].evaluate(
            caller,
            artifact_digest=body.artifact_digest,
            artifact_type=body.artifact_type,
            size=body.size,
            request_id=body.request_id,
            policy_version=body.policy_version,
        )

    @app.get("/admission/replay/{request_id}")
    def replay(request_id: str):
        return get_services()["admission"].replay(request_id)

    # ------------------------------------------------------------- audit
    @app.get("/audit")
    def query_audit(event_type: str | None = None,
                    request_id: str | None = None,
                    start: str | None = None,
                    end: str | None = None):
        audit = get_services()["audit"]
        if request_id:
            events = audit.by_request_id(request_id)
        elif event_type:
            events = audit.by_type(event_type)
        else:
            events = audit.between(start, end)
        return {"events": events, "count": len(events)}

    return app


app = create_app()
