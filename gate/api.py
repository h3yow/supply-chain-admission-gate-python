"""HTTP API wiring.

Endpoints
---------
GET  /health
POST /keys/rotate                 (caller: admin role)
POST /artifacts/sign              (caller: signer role)
POST /admission/evaluate          body: artifact + caller + optional version
GET  /policy/versions
POST /policy/publish              (caller: admin role)
POST /policy/rollback             (caller: admin role)
GET  /audit[?event_type=...]

Caller identity is supplied in the request body (``caller``) to keep the
service dependency-free and fully local.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from gate.errors import (
    GateError,
    KeyRevokedError,
    KeyUnknownError,
    PolicyDeniedError,
    PolicyNotFoundError,
    SignatureExpiredError,
    SignatureInvalidError,
    UnauthorizedCallerError,
)
from gate.models import Artifact, Caller, Decision, PolicyRule, RuleEffect
from gate.service import AdmissionService

_ERROR_STATUS = {
    UnauthorizedCallerError: 403,
    PolicyNotFoundError: 404,
    PolicyDeniedError: 403,
    SignatureInvalidError: 422,
    SignatureExpiredError: 422,
    KeyRevokedError: 422,
    KeyUnknownError: 404,
}


# -- request / response schemas ------------------------------------------


class CallerBody(BaseModel):
    identity: str
    roles: list[str] = Field(default_factory=list)


class ArtifactBody(BaseModel):
    digest: str
    name: str
    kind: str
    properties: dict = Field(default_factory=dict)


class EvaluateBody(BaseModel):
    artifact: ArtifactBody
    caller: CallerBody
    policy_version: int | None = None


class SignBody(BaseModel):
    artifact: ArtifactBody
    caller: CallerBody


class RuleBody(BaseModel):
    name: str
    artifact_kinds: list[str]
    effect: RuleEffect
    require_roles: list[str] = Field(default_factory=list)
    require_signature: bool = False
    property_match: dict = Field(default_factory=dict)


class PublishBody(BaseModel):
    rules: list[RuleBody]
    caller: CallerBody
    note: str = ""
    on_unmatched: Decision = Decision.MANUAL_REVIEW


class RollbackBody(BaseModel):
    version: int
    caller: CallerBody


class KeyActionBody(BaseModel):
    caller: CallerBody


class RevokeKeyBody(BaseModel):
    key_id: str
    caller: CallerBody


def create_app(service: AdmissionService | None = None) -> FastAPI:
    app = FastAPI(title="Supply-Chain Admission Gate", version="0.1.0")
    app.state.service = service or build_seeded_service()

    def svc() -> AdmissionService:
        return app.state.service

    @app.exception_handler(GateError)
    async def gate_error_handler(_request, exc: GateError):
        status = _ERROR_STATUS.get(type(exc), 400)
        return JSONResponse(
            status_code=status,
            content={"error": exc.code, "detail": str(exc)},
        )

    @app.get("/health")
    def health():
        s = svc()
        return {
            "status": "ok",
            "active_key_id": s.keys.active_key_id(),
            "current_policy_version": s.policies.current_version(),
        }

    @app.post("/artifacts/sign")
    def sign_artifact(body: SignBody):
        s = svc()
        artifact = _artifact(body.artifact)
        caller = _caller(body.caller)
        record, created = s.submit_signature(artifact, caller)
        return {
            "created": created,
            "artifact_digest": record.artifact_digest,
            "key_id": record.key_id,
            "signed_at": record.signed_at,
            "expires_at": record.expires_at,
            "caller": record.caller,
            "fingerprint": record.fingerprint(),
        }

    @app.post("/admission/evaluate")
    def evaluate(body: EvaluateBody):
        s = svc()
        result = s.evaluate(
            _artifact(body.artifact),
            _caller(body.caller),
            policy_version=body.policy_version,
        )
        return result.to_dict()

    @app.post("/keys/rotate")
    def rotate_key(body: KeyActionBody):
        s = svc()
        _require_admin(_caller(body.caller))
        return {"active_key_id": s.rotate_key()}

    @app.post("/keys/revoke")
    def revoke_key(body: RevokeKeyBody):
        s = svc()
        _require_admin(_caller(body.caller))
        s.revoke_key(body.key_id)
        return {"revoked": body.key_id}

    @app.post("/policy/publish")
    def publish_policy(body: PublishBody):
        s = svc()
        caller = _caller(body.caller)
        _require_admin(caller)
        version = s.publish_policy(
            [_rule(r) for r in body.rules],
            author=caller.identity,
            note=body.note,
            on_unmatched=body.on_unmatched,
        )
        return {"version": version}

    @app.post("/policy/rollback")
    def rollback_policy(body: RollbackBody):
        s = svc()
        _require_admin(_caller(body.caller))
        new_version = s.rollback_policy(body.version, body.caller.identity)
        return {"version": new_version}

    @app.get("/policy/versions")
    def list_policy_versions():
        s = svc()
        return [
            {
                "version": p.version,
                "created_at": p.created_at,
                "author": p.author,
                "note": p.note,
                "on_unmatched": p.on_unmatched.value,
                "rules": [r.name for r in p.rules],
            }
            for p in s.policies.list_versions()
        ]

    @app.get("/audit")
    def get_audit(event_type: str | None = None):
        return svc().audit_events(event_type)

    return app


# -- helpers --------------------------------------------------------------


def _artifact(body: ArtifactBody) -> Artifact:
    return Artifact(
        digest=body.digest,
        name=body.name,
        kind=body.kind,
        properties=body.properties,
    )


def _caller(body: CallerBody) -> Caller:
    return Caller(identity=body.identity, roles=frozenset(body.roles))


def _rule(body: RuleBody) -> PolicyRule:
    return PolicyRule(
        name=body.name,
        artifact_kinds=frozenset(body.artifact_kinds),
        effect=body.effect,
        require_roles=frozenset(body.require_roles),
        require_signature=body.require_signature,
        property_match=body.property_match,
    )


def _require_admin(caller: Caller) -> None:
    if "admin" not in caller.roles:
        raise UnauthorizedCallerError(
            f"caller {caller.identity!r} requires role 'admin'"
        )


def build_seeded_service() -> AdmissionService:
    """A ready-to-use local service: one key and a small demo policy."""
    service = AdmissionService()
    service.bootstrap_key()
    service.publish_policy(
        [
            PolicyRule(
                name="allow-signed-images",
                artifact_kinds=frozenset({"container-image"}),
                effect=RuleEffect.ALLOW,
                require_roles=frozenset({"deployer"}),
                require_signature=True,
            ),
            PolicyRule(
                name="deny-blocklisted-libs",
                artifact_kinds=frozenset({"library"}),
                effect=RuleEffect.DENY,
                property_match={"trusted": False},
            ),
        ],
        author="bootstrap",
        note="seed policy",
        on_unmatched=Decision.MANUAL_REVIEW,
    )
    return service
