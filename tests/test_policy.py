"""
Tests for pre-execution policy gate and built-in policies.
"""

from __future__ import annotations

import pytest

from agentledger.core.chain import ReceiptChainImpl
from agentledger.core.identity import AgentIdentityImpl
from agentledger.interfaces import ActionStatus, ActionType, Framework, PolicyViolationError
from agentledger.policies import (
    AllowAllPolicy,
    AllowlistPolicy,
    CompositePolicy,
    DenylistPolicy,
    HumanApprovalPolicy,
)
from tests.conftest import NoopBinding


def make_chain(tmp_path, policy=None):
    identity = AgentIdentityImpl.create(binding=NoopBinding())
    chain = ReceiptChainImpl(identity, storage_path=str(tmp_path), policy=policy)
    return identity, chain


# ── DenylistPolicy ────────────────────────────────────────────────────────────

def test_denylist_blocks_denied_tool(tmp_path):
    _, chain = make_chain(tmp_path, policy=DenylistPolicy(["rm_rf"]))

    with pytest.raises(PolicyViolationError) as exc_info:
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="rm_rf", payload="*")

    assert exc_info.value.tool_name == "rm_rf"
    assert "denylist" in exc_info.value.reason


def test_denylist_records_denied_receipt(tmp_path):
    _, chain = make_chain(tmp_path, policy=DenylistPolicy(["rm_rf"]))

    with pytest.raises(PolicyViolationError):
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="rm_rf")

    receipts = chain.iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.status == ActionStatus.DENIED
    assert receipts[0].action.tool_name == "rm_rf"
    assert receipts[0].action.error is not None
    assert "policy:denied" in receipts[0].action.error


def test_denylist_allows_other_tools(tmp_path):
    _, chain = make_chain(tmp_path, policy=DenylistPolicy(["rm_rf"]))

    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="web_search", payload="AI news")
    chain.finalize_last(status=ActionStatus.COMPLETED, result="results")

    receipts = chain.iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.status == ActionStatus.COMPLETED


# ── AllowlistPolicy ───────────────────────────────────────────────────────────

def test_allowlist_blocks_unlisted_tool(tmp_path):
    _, chain = make_chain(tmp_path, policy=AllowlistPolicy(["web_search"]))

    with pytest.raises(PolicyViolationError) as exc_info:
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="exec_shell")

    assert "allowlist" in exc_info.value.reason


def test_allowlist_permits_listed_tool(tmp_path):
    _, chain = make_chain(tmp_path, policy=AllowlistPolicy(["calculator"]))

    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="calculator", payload="2+2")
    chain.finalize_last(status=ActionStatus.COMPLETED, result="4")

    assert chain.iter_receipts()[0].action.status == ActionStatus.COMPLETED


def test_allowlist_always_permits_llm_invoke(tmp_path):
    _, chain = make_chain(tmp_path, policy=AllowlistPolicy([]))

    chain.append(ActionType.LLM_INVOKE, Framework.CUSTOM, payload="prompt")
    chain.finalize_last(status=ActionStatus.COMPLETED, result="response")

    assert chain.iter_receipts()[0].action.status == ActionStatus.COMPLETED


# ── HumanApprovalPolicy ───────────────────────────────────────────────────────

def test_human_approval_allow(tmp_path):
    policy = HumanApprovalPolicy(prompt_fn=lambda _: "y")
    _, chain = make_chain(tmp_path, policy=policy)

    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="send_email")
    chain.finalize_last(status=ActionStatus.COMPLETED, result="sent")

    assert chain.iter_receipts()[0].action.status == ActionStatus.COMPLETED


def test_human_approval_deny(tmp_path):
    policy = HumanApprovalPolicy(prompt_fn=lambda _: "n")
    _, chain = make_chain(tmp_path, policy=policy)

    with pytest.raises(PolicyViolationError) as exc_info:
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="send_email")

    assert "human operator denied" in exc_info.value.reason
    assert chain.iter_receipts()[0].action.status == ActionStatus.DENIED


# ── CompositePolicy ───────────────────────────────────────────────────────────

def test_composite_first_deny_wins(tmp_path):
    policy = CompositePolicy([
        DenylistPolicy(["rm_rf"]),
        AllowlistPolicy(["web_search"]),
    ])
    _, chain = make_chain(tmp_path, policy=policy)

    with pytest.raises(PolicyViolationError):
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="rm_rf")


def test_composite_all_allow(tmp_path):
    policy = CompositePolicy([AllowAllPolicy(), AllowlistPolicy(["search"])])
    _, chain = make_chain(tmp_path, policy=policy)

    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="search")
    chain.finalize_last(status=ActionStatus.COMPLETED, result="ok")

    assert chain.iter_receipts()[0].action.status == ActionStatus.COMPLETED


# ── Chain integrity after denial ──────────────────────────────────────────────

def test_chain_valid_after_denial(tmp_path):
    _, chain = make_chain(tmp_path, policy=DenylistPolicy(["bad_tool"]))

    with pytest.raises(PolicyViolationError):
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="bad_tool")

    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="good_tool")
    chain.finalize_last(status=ActionStatus.COMPLETED, result="ok")

    assert chain.verify() is True
    receipts = chain.iter_receipts()
    assert receipts[0].action.status == ActionStatus.DENIED
    assert receipts[1].action.status == ActionStatus.COMPLETED


def test_denied_receipt_in_cli_verify(tmp_path):
    from agentledger.cli.verify import verify_receipt_chain

    identity, chain = make_chain(tmp_path, policy=DenylistPolicy(["exec"]))

    with pytest.raises(PolicyViolationError):
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="exec")

    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="search")
    chain.finalize_last(status=ActionStatus.COMPLETED, result="results")

    jsonl = list(tmp_path.glob("*.jsonl"))[0]
    ok, msg = verify_receipt_chain(jsonl, agent_public_key=bytes.fromhex(identity.agent_id))
    assert ok is True, msg


def test_no_policy_allows_everything(tmp_path):
    _, chain = make_chain(tmp_path, policy=None)

    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="anything")
    chain.finalize_last(status=ActionStatus.COMPLETED, result="ok")

    assert chain.iter_receipts()[0].action.status == ActionStatus.COMPLETED
