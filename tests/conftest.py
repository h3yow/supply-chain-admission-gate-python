"""Shared fixtures: temp data dir, fixed clock, services and HTTP client."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from admission import app as app_module
from admission.audit import AuditService
from admission.clock import FixedClock
from admission.engine import AdmissionService
from admission.keys import KeyService
from admission.policy import PolicyService
from admission.signing import SigningService
from admission.storage import Store


@pytest.fixture()
def tmp_data_dir(tmp_path):
    return str(tmp_path / "data")


@pytest.fixture()
def clock():
    return FixedClock(datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC))


@pytest.fixture()
def store(tmp_data_dir):
    return Store(tmp_data_dir)


@pytest.fixture()
def services(store, clock):
    keys = KeyService(store, clock)
    signing = SigningService(store, clock, keys)
    policy = PolicyService(store, clock)
    audit = AuditService(store)
    admission = AdmissionService(store, clock, signing, policy)
    return {"store": store, "clock": clock, "keys": keys, "signing": signing,
            "policy": policy, "audit": audit, "admission": admission}


@pytest.fixture()
def client(tmp_data_dir, monkeypatch):
    # Routes resolve the directory lazily through ADMISSION_DATA_DIR, so point
    # the env var at the per-test temp dir rather than passing it directly.
    monkeypatch.setenv("ADMISSION_DATA_DIR", tmp_data_dir)
    app_module.get_services.cache_clear()
    app_module.get_services(tmp_data_dir)
    with TestClient(app_module.app) as c:
        yield c
    app_module.get_services.cache_clear()


@pytest.fixture()
def actors():
    """Identity headers used by the HTTP tests."""
    return {
        "admin": {"X-Caller-Id": "admin",
                  "X-Caller-Roles": "key_admin,policy_admin"},
        "ci": {"X-Caller-Id": "ci",
               "X-Caller-Roles": "signer,deployer",
               "X-Caller-Key-Grants": "k1"},
        "ci_new": {"X-Caller-Id": "ci",
                   "X-Caller-Roles": "signer,deployer",
                   "X-Caller-Key-Grants": "k1-new"},
        "viewer": {"X-Caller-Id": "viewer", "X-Caller-Roles": "viewer"},
        "evil": {"X-Caller-Id": "evil",
                 "X-Caller-Roles": "signer",
                 "X-Caller-Key-Grants": "k1"},
        "anonymous": {},
    }
