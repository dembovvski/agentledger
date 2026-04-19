"""
tests/test_cross_agent.py — Cross-agent reference flow
======================================================

Flow:
  Agent A: appends a TOOL_CALL receipt, finalizes it COMPLETED
  Agent B: appends a DECISION receipt with cross_ref to A's receipt (PENDING)
  Agent B: calls confirm_cross_ref() → CONFIRMED receipt appended
  Orchestrator: verify_external_chain(A) + verify_external_chain(B)
  resolve_cross_ref: lightweight check from B's perspective
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from agentledger.core.chain import ReceiptChainImpl
from agentledger.core.identity import AgentIdentityImpl
from agentledger.interfaces import (
    ActionStatus,
    ActionType,
    CrossAgentRef,
    CrossAgentRefStatus,
    Framework,
)
from agentledger.cli.verify import verify_receipt_chain as cli_verify_receipt_chain


class NoopBinding:
    """Minimal binding for tests — no external keys required."""
    binding_type = "custom"

    def bind(self, agent_public_key: bytes, principal_id: str) -> bytes:
        return b"\x00" * 64

    def verify(self, agent_public_key: bytes, principal_id: str, signature: bytes) -> bool:
        return True

    def serialize_binding_info(self):
        return {}


@pytest.fixture
def tmp_storage():
    """Shared storage directory for both agents (needed for cross-ref resolution)."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def identity_a(tmp_storage):
    return AgentIdentityImpl.create(binding=NoopBinding())


@pytest.fixture
def identity_b(tmp_storage):
    return AgentIdentityImpl.create(binding=NoopBinding())


@pytest.fixture
def chain_a(identity_a, tmp_storage):
    return ReceiptChainImpl(
        identity_a,
        storage_path=str(tmp_storage),  # shared dir — resolve_cross_ref searches here
        checkpoint_interval=100,
    )


@pytest.fixture
def chain_b(identity_b, tmp_storage):
    return ReceiptChainImpl(
        identity_b,
        storage_path=str(tmp_storage),  # shared dir — resolve_cross_ref searches here
        checkpoint_interval=100,
    )


# ── Test 1: Agent A writes a receipt ─────────────────────────────────────────

def test_agent_a_writes_completed_receipt(chain_a):
    """Agent A: tool_call → COMPLETED."""
    receipt_id = chain_a.append(
        ActionType.TOOL_CALL,
        Framework.CUSTOM,
        tool_name="file_read",
        payload={"path": "/data/config.yaml"},
    )
    chain_a.finalize_last(status=ActionStatus.COMPLETED, result={"lines": 42})

    receipt = chain_a.get_receipt(receipt_id)
    assert receipt.action.status == ActionStatus.COMPLETED
    assert receipt.action.tool_name == "file_read"
    assert chain_a.verify() is True


# ── Test 2: Agent B references A's receipt (PENDING) ────────────────────────

def test_agent_b_references_a_pending(chain_a, chain_b):
    """Agent B creates a PENDING cross-agent reference to Agent A's receipt."""
    # A writes a receipt first
    a_receipt_id = chain_a.append(
        ActionType.TOOL_CALL,
        Framework.CUSTOM,
        tool_name="file_read",
        payload={"path": "/data/config.yaml"},
    )
    chain_a.finalize_last(status=ActionStatus.COMPLETED, result={"lines": 42})

    # B appends a DECISION that references A's receipt
    b_receipt_id = chain_b.append(
        ActionType.DECISION,
        Framework.CUSTOM,
        cross_agent_ref=CrossAgentRef(
            target_agent_id=chain_a.identity.agent_id,
            ref_receipt_id=a_receipt_id,
            status=CrossAgentRefStatus.PENDING,
        ),
    )
    chain_b.finalize_last(status=ActionStatus.COMPLETED, result={"decision": "approved"})

    b_receipt = chain_b.get_receipt(b_receipt_id)
    assert b_receipt.cross_agent_ref is not None
    assert b_receipt.cross_agent_ref.status == CrossAgentRefStatus.PENDING
    assert b_receipt.cross_agent_ref.ref_receipt_id == a_receipt_id
    assert chain_b.verify() is True


# ── Test 3: Agent B confirms the reference ───────────────────────────────────

def test_agent_b_confirms_cross_ref(chain_a, chain_b):
    """Agent B calls confirm_cross_ref → new CONFIRMED receipt appended."""
    # A writes a receipt
    a_receipt_id = chain_a.append(
        ActionType.TOOL_CALL,
        Framework.CUSTOM,
        tool_name="file_read",
        payload={"path": "/data/config.yaml"},
    )
    chain_a.finalize_last(status=ActionStatus.COMPLETED, result={"lines": 42})

    # B references it (PENDING)
    b_receipt_id = chain_b.append(
        ActionType.DECISION,
        Framework.CUSTOM,
        cross_agent_ref=CrossAgentRef(
            target_agent_id=chain_a.identity.agent_id,
            ref_receipt_id=a_receipt_id,
            status=CrossAgentRefStatus.PENDING,
        ),
    )
    chain_b.finalize_last(status=ActionStatus.COMPLETED, result={"decision": "approved"})

    # B confirms the reference
    confirm_receipt_id = chain_b.confirm_cross_ref(b_receipt_id)

    # A new receipt was appended (append-only — original is NOT modified)
    all_receipts = chain_b.iter_receipts()
    assert len(all_receipts) == 2  # original + confirm

    confirm_receipt = chain_b.get_receipt(confirm_receipt_id)
    assert confirm_receipt.action.type == ActionType.CROSS_AGENT
    assert confirm_receipt.action.status == ActionStatus.COMPLETED
    assert confirm_receipt.cross_agent_ref is not None
    assert confirm_receipt.cross_agent_ref.status == CrossAgentRefStatus.CONFIRMED
    # CONFIRMATION.receipt_ref points to the LOCAL receipt being confirmed (b_receipt_id),
    # not to the external agent's receipt. The external agent is identified by target_agent_id.
    assert confirm_receipt.cross_agent_ref.ref_receipt_id == b_receipt_id
    assert confirm_receipt.cross_agent_ref.target_agent_id == chain_a.identity.agent_id

    # Chain still verifies
    assert chain_b.verify() is True


# ── Test 4: resolve_cross_ref (lightweight check) ────────────────────────────

def test_resolve_cross_ref_returns_true_for_completed(chain_a, chain_b):
    """resolve_cross_ref returns True when referenced receipt is COMPLETED."""
    a_receipt_id = chain_a.append(
        ActionType.TOOL_CALL,
        Framework.CUSTOM,
        tool_name="file_read",
        payload={"path": "/data/config.yaml"},
    )
    chain_a.finalize_last(status=ActionStatus.COMPLETED, result={"lines": 42})

    ref = CrossAgentRef(
        target_agent_id=chain_a.identity.agent_id,
        ref_receipt_id=a_receipt_id,
        status=CrossAgentRefStatus.PENDING,
    )
    assert chain_b.resolve_cross_ref(ref) is True


def test_resolve_cross_ref_returns_false_for_nonexistent(chain_b):
    """resolve_cross_ref returns False when referenced receipt doesn't exist."""
    ref = CrossAgentRef(
        target_agent_id="a" * 64,
        ref_receipt_id="nonexistent-receipt-id",
        status=CrossAgentRefStatus.PENDING,
    )
    assert chain_b.resolve_cross_ref(ref) is False


def test_resolve_cross_ref_returns_false_for_pending(chain_a, chain_b):
    """resolve_cross_ref returns False when referenced receipt is still PENDING."""
    # A appends but does NOT finalize
    a_receipt_id = chain_a.append(
        ActionType.TOOL_CALL,
        Framework.CUSTOM,
        tool_name="file_read",
        payload={"path": "/data/config.yaml"},
    )
    # A never calls finalize_last — receipt stays PENDING

    ref = CrossAgentRef(
        target_agent_id=chain_a.identity.agent_id,
        ref_receipt_id=a_receipt_id,
        status=CrossAgentRefStatus.PENDING,
    )
    assert chain_b.resolve_cross_ref(ref) is False


# ── Test 5: Error cases ─────────────────────────────────────────────────────

def test_confirm_cross_ref_keyerror_when_not_found(chain_b):
    """confirm_cross_ref raises KeyError when receipt_id doesn't exist."""
    with pytest.raises(KeyError):
        chain_b.confirm_cross_ref("nonexistent-receipt-id")


def test_confirm_cross_ref_valueerror_when_no_cross_ref(chain_a, chain_b):
    """confirm_cross_ref raises ValueError when receipt has no cross_agent_ref."""
    receipt_id = chain_b.append(
        ActionType.DECISION,
        Framework.CUSTOM,
    )
    chain_b.finalize_last(status=ActionStatus.COMPLETED)

    with pytest.raises(ValueError, match="no cross_agent_ref"):
        chain_b.confirm_cross_ref(receipt_id)


def test_confirm_cross_ref_valueerror_when_already_confirmed(chain_a, chain_b):
    """confirm_cross_ref raises ValueError when ref is already CONFIRMED."""
    a_receipt_id = chain_a.append(
        ActionType.TOOL_CALL,
        Framework.CUSTOM,
        tool_name="file_read",
        payload={"path": "/data/config.yaml"},
    )
    chain_a.finalize_last(status=ActionStatus.COMPLETED, result={"lines": 42})

    b_receipt_id = chain_b.append(
        ActionType.DECISION,
        Framework.CUSTOM,
        cross_agent_ref=CrossAgentRef(
            target_agent_id=chain_a.identity.agent_id,
            ref_receipt_id=a_receipt_id,
            status=CrossAgentRefStatus.PENDING,
        ),
    )
    chain_b.finalize_last(status=ActionStatus.COMPLETED)

    # First confirmation works
    chain_b.confirm_cross_ref(b_receipt_id)

    # Second confirmation raises
    with pytest.raises(ValueError, match="already CONFIRMED"):
        chain_b.confirm_cross_ref(b_receipt_id)


# ── Test 6: Orchestrator verifies both chains ────────────────────────────────

def test_orchestrator_verifies_external_chain_via_cli_verify(chain_a, chain_b):
    """Orchestrator uses verify_receipt_chain to audit Agent A and B's chains."""
    # A writes a COMPLETED receipt
    a_receipt_id = chain_a.append(
        ActionType.TOOL_CALL,
        Framework.CUSTOM,
        tool_name="file_read",
        payload={"path": "/data/config.yaml"},
    )
    chain_a.finalize_last(status=ActionStatus.COMPLETED, result={"lines": 42})

    # B references A and confirms
    b_receipt_id = chain_b.append(
        ActionType.DECISION,
        Framework.CUSTOM,
        cross_agent_ref=CrossAgentRef(
            target_agent_id=chain_a.identity.agent_id,
            ref_receipt_id=a_receipt_id,
            status=CrossAgentRefStatus.PENDING,
        ),
    )
    chain_b.finalize_last(status=ActionStatus.COMPLETED)
    chain_b.confirm_cross_ref(b_receipt_id)

    # Orchestrator verifies Agent A's chain
    a_log_file = chain_a._log_file
    ok_a, msg_a = cli_verify_receipt_chain(
        a_log_file,
        agent_public_key=bytes.fromhex(chain_a.identity.agent_id),
    )
    assert ok_a is True
    assert "verified" in msg_a

    # Orchestrator verifies Agent B's chain
    b_log_file = chain_b._log_file
    ok_b, msg_b = cli_verify_receipt_chain(
        b_log_file,
        agent_public_key=bytes.fromhex(chain_b.identity.agent_id),
    )
    assert ok_b is True
    assert "verified" in msg_b


# ── Test 7: append-only — original receipt is never modified ─────────────────

def test_append_only_original_receipt_not_modified(chain_a, chain_b):
    """Confirming a cross_ref does NOT modify the original receipt's signature."""
    a_receipt_id = chain_a.append(
        ActionType.TOOL_CALL,
        Framework.CUSTOM,
        tool_name="file_read",
        payload={"path": "/data/config.yaml"},
    )
    chain_a.finalize_last(status=ActionStatus.COMPLETED, result={"lines": 42})

    b_receipt_id = chain_b.append(
        ActionType.DECISION,
        Framework.CUSTOM,
        cross_agent_ref=CrossAgentRef(
            target_agent_id=chain_a.identity.agent_id,
            ref_receipt_id=a_receipt_id,
            status=CrossAgentRefStatus.PENDING,
        ),
    )
    chain_b.finalize_last(status=ActionStatus.COMPLETED)

    original_b_receipt = chain_b.get_receipt(b_receipt_id)
    original_sig = original_b_receipt.signature

    # Confirm
    chain_b.confirm_cross_ref(b_receipt_id)

    # Original receipt is unchanged
    still_original = chain_b.get_receipt(b_receipt_id)
    assert still_original.signature == original_sig
    assert still_original.cross_agent_ref.status == CrossAgentRefStatus.PENDING


# ── Test 8: Chain with multiple cross-refs ───────────────────────────────────

def test_multiple_cross_refs_same_agent(chain_a, chain_b):
    """Agent B can reference multiple receipts from Agent A."""
    # A writes two receipts
    a_r1 = chain_a.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="read")
    chain_a.finalize_last(status=ActionStatus.COMPLETED)

    a_r2 = chain_a.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="write")
    chain_a.finalize_last(status=ActionStatus.COMPLETED)

    # B references both
    b_r1 = chain_b.append(
        ActionType.DECISION,
        Framework.CUSTOM,
        cross_agent_ref=CrossAgentRef(
            target_agent_id=chain_a.identity.agent_id,
            ref_receipt_id=a_r1,
            status=CrossAgentRefStatus.PENDING,
        ),
    )
    chain_b.finalize_last(status=ActionStatus.COMPLETED)

    b_r2 = chain_b.append(
        ActionType.DECISION,
        Framework.CUSTOM,
        cross_agent_ref=CrossAgentRef(
            target_agent_id=chain_a.identity.agent_id,
            ref_receipt_id=a_r2,
            status=CrossAgentRefStatus.PENDING,
        ),
    )
    chain_b.finalize_last(status=ActionStatus.COMPLETED)

    # Confirm both
    chain_b.confirm_cross_ref(b_r1)
    chain_b.confirm_cross_ref(b_r2)

    all_receipts = chain_b.iter_receipts()
    assert len(all_receipts) == 4  # 2 original + 2 confirmations

    assert chain_b.verify() is True


# ── Test 9: resolve_cross_ref with None fields ───────────────────────────────

def test_resolve_cross_ref_with_none_fields(chain_b):
    """resolve_cross_ref returns False when target_agent_id or ref_receipt_id is None."""
    ref_none_target = CrossAgentRef(
        target_agent_id=None,
        ref_receipt_id="some-id",
        status=CrossAgentRefStatus.PENDING,
    )
    assert chain_b.resolve_cross_ref(ref_none_target) is False

    ref_none_id = CrossAgentRef(
        target_agent_id="a" * 64,
        ref_receipt_id=None,
        status=CrossAgentRefStatus.PENDING,
    )
    assert chain_b.resolve_cross_ref(ref_none_id) is False
