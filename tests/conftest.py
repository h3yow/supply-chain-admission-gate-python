"""Shared pytest fixtures/logging.

The service logs an input summary and the decision basis at INFO; configure
the ``gate`` logger so these lines appear in unit-test output.
"""

import logging
import sys

import pytest

from gate.models import Artifact, Caller, Decision, PolicyRule, RuleEffect
from gate.service import AdmissionService

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(name)s | %(message)s"))
gate_logger = logging.getLogger("gate")
gate_logger.setLevel(logging.INFO)
gate_logger.addHandler(handler)
gate_logger.propagate = False




@pytest.fixture
def clock():
    class FakeClock:
        def __init__(self):
            self.now = 1_000_000.0

        def __call__(self):
            return self.now

        def advance(self, seconds):
            self.now += seconds

    return FakeClock()


@pytest.fixture
def service(clock):
    return build_demo_service(AdmissionService(clock=clock, signature_ttl=100.0))


def build_demo_service(service: AdmissionService) -> AdmissionService:
    service.bootstrap_key()
    service.publish_policy(
        [
            PolicyRule(
                name="signed-images-need-deployer",
                artifact_kinds=frozenset({"container-image"}),
                effect=RuleEffect.ALLOW,
                require_roles=frozenset({"deployer"}),
                require_signature=True,
            ),
            PolicyRule(
                name="deny-untrusted-libs",
                artifact_kinds=frozenset({"library"}),
                effect=RuleEffect.DENY,
                property_match={"trusted": False},
            ),
            PolicyRule(
                name="review-config",
                artifact_kinds=frozenset({"config"}),
                effect=RuleEffect.REVIEW,
            ),
        ],
        author="tester",
        note="demo policy",
        on_unmatched=Decision.MANUAL_REVIEW,
    )
    return service


@pytest.fixture
def image():
    return Artifact(
        digest="sha256:abc", name="app:1", kind="container-image"
    )


@pytest.fixture
def signed_image(service, image):
    signer = Caller("signer-1", frozenset({"signer"}))
    service.submit_signature(image, signer)
    return image


@pytest.fixture
def deployer():
    return Caller("deployer-1", frozenset({"deployer"}))


@pytest.fixture
def guest():
    return Caller("guest-1", frozenset())
