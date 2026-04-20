"""
Tests verifying security fixes from the v0.4 audit.

Covers:
  - policy_hash in signed receipt payload (willamhou RFC comment)
  - get_receipt() returns deep copy, not live reference
  - resolve_cross_ref() verifies Ed25519 signature on referenced receipt
  - AgentIdentityImpl.save_private_key() + load() key persistence
"""

from __future__ import annotations

import json
import copy
from pathlib import Path

import pytest

from agentledger.core.chain import ReceiptChainImpl
from agentledger.core.identity import AgentIdentityImpl
from agentledger.core.receipt import canonicalise_for_signing
from agentledger.interfaces import (
    ActionStatus,
    ActionType,
    CrossAgentRef,
    CrossAgentRefStatus,
    Framework,
    PolicyViolationError,
)
from agentledger.policies import AllowAllPolicy, AllowlistPolicy, DenylistPolicy, CompositePolicy


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def identity(noop_binding):
    return AgentIdentityImpl.create(binding=noop_binding)


@pytest.fixture
def identity2(noop_binding):
    return AgentIdentityImpl.create(binding=noop_binding)


def make_chain(identity, tmp_path, policy=None):
    return ReceiptChainImpl(identity, storage_path=str(tmp_path), policy=policy)


# ── policy_hash in signed payload ─────────────────────────────────────────────

def test_policy_attestation_present_in_allowed_receipt(identity, tmp_path):
    policy = DenylistPolicy(["rm_rf"])
    chain = make_chain(identity, tmp_path, policy=policy)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="safe_tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    r = chain.iter_receipts()[0]
    assert r.action.policy_attestation is not None
    assert r.action.policy_attestation.policy_digest == policy.policy_id
    assert r.action.policy_attestation.policy_decision == "permit"


def test_policy_attestation_present_in_denied_receipt(identity, tmp_path):
    policy = DenylistPolicy(["bad_tool"])
    chain = make_chain(identity, tmp_path, policy=policy)
    with pytest.raises(PolicyViolationError):
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="bad_tool")
    r = chain.iter_receipts()[0]
    assert r.action.status == ActionStatus.DENIED
    assert r.action.policy_attestation is not None
    assert r.action.policy_attestation.policy_digest == policy.policy_id
    assert r.action.policy_attestation.policy_decision == "deny"


def test_policy_attestation_is_inside_signed_payload(identity, tmp_path):
    """policy_attestation must be in the bytes that get signed — not metadata."""
    policy = AllowlistPolicy(["search"])
    chain = make_chain(identity, tmp_path, policy=policy)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="search")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    r = chain.iter_receipts()[0]

    payload_bytes = canonicalise_for_signing(r)
    payload_dict = json.loads(payload_bytes)
    attestation = payload_dict["action"]["policy_attestation"]
    assert attestation is not None
    assert attestation["policy_digest"] == policy.policy_id
    assert attestation["policy_decision"] == "permit"


def test_policy_attestation_none_when_no_policy(identity, tmp_path):
    chain = make_chain(identity, tmp_path, policy=None)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="any_tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    r = chain.iter_receipts()[0]
    assert r.action.policy_attestation is None


def test_policy_attestation_allow_all_policy(identity, tmp_path):
    policy = AllowAllPolicy()
    chain = make_chain(identity, tmp_path, policy=policy)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="any_tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    r = chain.iter_receipts()[0]
    assert r.action.policy_attestation is not None
    assert r.action.policy_attestation.policy_digest.startswith("sha256:")
    assert len(r.action.policy_attestation.policy_digest) == 7 + 64
    assert r.action.policy_attestation.policy_decision == "permit"


def test_policy_attestation_composite_round_trip(identity, tmp_path):
    policy = CompositePolicy([DenylistPolicy(["rm_rf"]), AllowlistPolicy(["search"])])
    chain = make_chain(identity, tmp_path, policy=policy)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="search")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    r = chain.iter_receipts()[0]
    assert r.action.policy_attestation is not None
    assert r.action.policy_attestation.policy_digest == policy.policy_id
    assert r.action.policy_attestation.policy_decision == "permit"


def test_policy_digest_format_all_policies():
    """All policy classes must return 'sha256:<64-hex>' format."""
    import re
    pattern = re.compile(r"sha256:[0-9a-f]{64}")
    policies = [
        AllowAllPolicy(),
        DenylistPolicy(["a"]),
        AllowlistPolicy(["b"]),
        CompositePolicy([DenylistPolicy(["x"])]),
    ]
    for p in policies:
        assert pattern.fullmatch(p.policy_id), f"{type(p).__name__}.policy_id format wrong: {p.policy_id!r}"


def test_policy_id_stable_for_same_config():
    p1 = DenylistPolicy(["a", "b", "c"])
    p2 = DenylistPolicy(["c", "a", "b"])  # different order, same set
    assert p1.policy_id == p2.policy_id


def test_policy_id_differs_for_different_config():
    p1 = DenylistPolicy(["a"])
    p2 = DenylistPolicy(["b"])
    assert p1.policy_id != p2.policy_id


def test_composite_policy_id_includes_sub_policies():
    deny = DenylistPolicy(["rm_rf"])
    allow = AllowlistPolicy(["search"])
    composite = CompositePolicy([deny, allow])
    assert deny.policy_id in composite.policy_id or composite.policy_id != deny.policy_id
    # Composite ID must differ from any single sub-policy ID
    assert composite.policy_id != deny.policy_id
    assert composite.policy_id != allow.policy_id


# ── get_receipt() returns deep copy ──────────────────────────────────────────

def test_get_receipt_returns_deep_copy(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    receipts = chain.iter_receipts()
    receipt_id = receipts[0].receipt_id

    r1 = chain.get_receipt(receipt_id)
    r1.action.error = "mutated externally"

    r2 = chain.get_receipt(receipt_id)
    assert r2.action.error is None, "get_receipt() must return a copy — mutation must not affect chain"


def test_get_receipt_copy_does_not_affect_verify(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    receipt_id = chain.iter_receipts()[0].receipt_id

    r = chain.get_receipt(receipt_id)
    r.signature = "deadbeef" * 16  # corrupt the copy

    assert chain.verify() is True  # internal chain unaffected


# ── resolve_cross_ref() with signature verification ───────────────────────────

def test_resolve_cross_ref_verifies_signature(identity, identity2, tmp_path):
    """resolve_cross_ref() must reject a receipt with an invalid signature."""
    chain_a = make_chain(identity, tmp_path)
    chain_b = make_chain(identity2, tmp_path)

    # Agent A completes a tool call
    rid = chain_a.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="fetch")
    chain_a.finalize_last(status=ActionStatus.COMPLETED)

    # Agent B creates a cross-agent ref pointing to Agent A's receipt
    ref = CrossAgentRef(
        target_agent_id=identity.agent_id,
        ref_receipt_id=rid,
        status=CrossAgentRefStatus.PENDING,
    )
    assert chain_b.resolve_cross_ref(ref) is True

    # Now tamper with Agent A's JSONL — corrupt the signature
    jsonl_file = chain_a._log_file
    lines = jsonl_file.read_text().splitlines()
    tampered = []
    for line in lines:
        obj = json.loads(line)
        if obj.get("receipt_id") == rid:
            obj["signature"] = "aa" * 64  # invalid signature
        tampered.append(json.dumps(obj, separators=(",", ":"), sort_keys=True))
    jsonl_file.write_text("\n".join(tampered) + "\n")

    # After tampering, resolve_cross_ref must return False
    assert chain_b.resolve_cross_ref(ref) is False


def test_resolve_cross_ref_rejects_wrong_agent_id(identity, identity2, tmp_path):
    """resolve_cross_ref() with wrong target_agent_id must return False."""
    chain_a = make_chain(identity, tmp_path)
    rid = chain_a.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="fetch")
    chain_a.finalize_last(status=ActionStatus.COMPLETED)

    chain_b = make_chain(identity2, tmp_path)
    # Point to identity2's agent_id instead of identity's — wrong key
    ref = CrossAgentRef(
        target_agent_id=identity2.agent_id,
        ref_receipt_id=rid,
        status=CrossAgentRefStatus.PENDING,
    )
    assert chain_b.resolve_cross_ref(ref) is False


# ── save_private_key() + load() key persistence ───────────────────────────────

def test_save_and_load_roundtrip(noop_binding, tmp_path):
    identity = AgentIdentityImpl.create(binding=noop_binding)
    identity_path = str(tmp_path / "identity.json")
    key_path = str(tmp_path / "identity.key")

    identity.save(identity_path)
    identity.save_private_key(key_path)

    loaded = AgentIdentityImpl.load(identity_path, key_path)
    assert loaded.agent_id == identity.agent_id
    assert loaded.principal_id == identity.principal_id


def test_loaded_identity_can_verify_old_receipts(noop_binding, tmp_path):
    """Receipts signed by original identity must verify with loaded identity."""
    identity = AgentIdentityImpl.create(binding=noop_binding)
    identity.save(str(tmp_path / "identity.json"))
    identity.save_private_key(str(tmp_path / "identity.key"))

    chain = ReceiptChainImpl(identity, storage_path=str(tmp_path / "receipts"))
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)

    # Load identity from disk and verify chain from disk
    loaded = AgentIdentityImpl.load(
        str(tmp_path / "identity.json"),
        str(tmp_path / "identity.key"),
    )
    from agentledger.cli.verify import verify_receipt_chain
    ok, msg = verify_receipt_chain(
        chain._log_file,
        agent_public_key=bytes.fromhex(loaded.agent_id),
    )
    assert ok, msg


def test_private_key_file_permissions(noop_binding, tmp_path):
    import os, stat
    identity = AgentIdentityImpl.create(binding=noop_binding)
    key_path = tmp_path / "identity.key"
    identity.save_private_key(str(key_path))
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    assert mode == 0o400, f"Expected 0o400, got {oct(mode)}"
