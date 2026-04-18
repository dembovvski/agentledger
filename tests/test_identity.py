"""Tests for AgentIdentityImpl — Ed25519 keypair + principal binding."""

import pytest
from agentledger.core.identity import AgentIdentityImpl
from agentledger.interfaces import PrincipalBinding
from tests.conftest import NoopBinding


def test_create_generates_unique_agent_ids():
    b = NoopBinding()
    id1 = AgentIdentityImpl.create(binding=b)
    id2 = AgentIdentityImpl.create(binding=b)
    assert id1.agent_id != id2.agent_id


def test_agent_id_is_64_hex_chars(identity):
    assert len(identity.agent_id) == 64
    int(identity.agent_id, 16)  # raises if not valid hex


def test_sign_returns_64_bytes(identity):
    sig = identity.sign(b"hello")
    assert len(sig) == 64


def test_verify_signature_valid(identity):
    payload = b"test payload"
    sig = identity.sign(payload)
    assert identity.verify_signature(payload, sig) is True


def test_verify_signature_tampered_payload(identity):
    sig = identity.sign(b"original")
    assert identity.verify_signature(b"tampered", sig) is False


def test_verify_signature_tampered_signature(identity):
    payload = b"test"
    sig = bytearray(identity.sign(payload))
    sig[0] ^= 0xFF
    assert identity.verify_signature(payload, bytes(sig)) is False


def test_cross_identity_signatures_dont_verify(identity, identity2):
    payload = b"data"
    sig = identity.sign(payload)
    assert identity2.verify_signature(payload, sig) is False


def test_binding_type_stored(identity):
    assert identity.binding_type == "custom"


def test_serialize_contains_required_fields(identity):
    data = identity.serialize()
    for field in ("agent_id", "principal_id", "binding_type", "binding_signature",
                  "created_at", "schema_version"):
        assert field in data, f"missing field: {field}"


def test_serialize_agent_id_matches(identity):
    data = identity.serialize()
    assert data["agent_id"] == identity.agent_id


def test_derived_from_stored(noop_binding, identity):
    child = AgentIdentityImpl.create(
        binding=noop_binding, derived_from=identity.agent_id
    )
    assert child.serialize()["derived_from"] == identity.agent_id


def test_principal_id_defaults_to_pubkey_hex(noop_binding):
    identity = AgentIdentityImpl.create(binding=noop_binding)
    assert identity.principal_id == identity.agent_id


def test_custom_principal_id(noop_binding):
    identity = AgentIdentityImpl.create(
        binding=noop_binding, principal_id="user@example.com"
    )
    assert identity.principal_id == "user@example.com"
