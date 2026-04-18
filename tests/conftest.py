"""Shared fixtures for AgentLedger test suite."""

import pytest
from agentledger.core.identity import AgentIdentityImpl
from agentledger.interfaces import PrincipalBinding


class NoopBinding(PrincipalBinding):
    """Minimal binding for tests — no external keys required."""
    binding_type = "custom"

    def bind(self, agent_public_key: bytes, principal_id: str) -> bytes:
        return b"\x00" * 64

    def verify(self, agent_public_key: bytes, principal_id: str, signature: bytes) -> bool:
        return True

    def serialize_binding_info(self):
        return {}


@pytest.fixture
def noop_binding():
    return NoopBinding()


@pytest.fixture
def identity(noop_binding):
    return AgentIdentityImpl.create(binding=noop_binding)


@pytest.fixture
def identity2(noop_binding):
    return AgentIdentityImpl.create(binding=noop_binding)
