"""
Tests for dashboard/reader.py — JSONL scanning and receipt parsing.
Does not require fastapi installed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentledger.core.chain import ReceiptChainImpl
from agentledger.core.identity import AgentIdentityImpl
from agentledger.dashboard.reader import (
    AgentSummary,
    ReceiptRow,
    read_receipts,
    scan_agents,
)
from agentledger.interfaces import ActionStatus, ActionType, CrossAgentRef, CrossAgentRefStatus, Framework
from tests.conftest import NoopBinding


def make_chain(tmp_path: Path):
    identity = AgentIdentityImpl.create(binding=NoopBinding())
    chain = ReceiptChainImpl(identity, storage_path=str(tmp_path))
    return identity, chain


# ── read_receipts ─────────────────────────────────────────────────────────────

def test_read_receipts_returns_rows(tmp_path):
    _, chain = make_chain(tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="search", payload="query")
    chain.finalize_last(status=ActionStatus.COMPLETED, result="results")

    jsonl = list(tmp_path.glob("*.jsonl"))[0]
    rows = read_receipts(jsonl)
    assert len(rows) == 1
    assert rows[0].action_type == "tool_call"
    assert rows[0].status == "completed"
    assert rows[0].tool_name == "search"


def test_read_receipts_skips_checkpoints(tmp_path):
    _, chain = make_chain(tmp_path)
    chain.checkpoint_interval = 2
    for i in range(4):
        chain.append(ActionType.LLM_INVOKE, Framework.CUSTOM, payload=f"p{i}")
        chain.finalize_last(status=ActionStatus.COMPLETED)

    jsonl = list(tmp_path.glob("*.jsonl"))[0]
    rows = read_receipts(jsonl)
    assert len(rows) == 4  # checkpoints excluded


def test_read_receipts_includes_denied(tmp_path):
    from agentledger.policies import DenylistPolicy
    _, chain = make_chain(tmp_path)
    chain._policy = DenylistPolicy(["rm_rf"])

    from agentledger.interfaces import PolicyViolationError
    with pytest.raises(PolicyViolationError):
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="rm_rf")

    jsonl = list(tmp_path.glob("*.jsonl"))[0]
    rows = read_receipts(jsonl)
    assert len(rows) == 1
    assert rows[0].status == "denied"


def test_read_receipts_cross_ref_populated(tmp_path):
    _, chain = make_chain(tmp_path)
    chain.append(
        ActionType.DECISION,
        Framework.CUSTOM,
        cross_agent_ref=CrossAgentRef(
            target_agent_id="a" * 64,
            ref_receipt_id="ref-123",
            status=CrossAgentRefStatus.PENDING,
        ),
    )
    chain.finalize_last(status=ActionStatus.COMPLETED)

    jsonl = list(tmp_path.glob("*.jsonl"))[0]
    rows = read_receipts(jsonl)
    assert rows[0].has_cross_ref is True
    assert rows[0].cross_agent_ref["ref_receipt_id"] == "ref-123"


def test_receipt_row_status_class(tmp_path):
    _, chain = make_chain(tmp_path)
    chain.append(ActionType.LLM_INVOKE, Framework.CUSTOM)
    chain.finalize_last(status=ActionStatus.FAILED, error="timeout")

    jsonl = list(tmp_path.glob("*.jsonl"))[0]
    rows = read_receipts(jsonl)
    assert rows[0].status_class == "status-failed"


def test_receipt_row_short_id(tmp_path):
    _, chain = make_chain(tmp_path)
    chain.append(ActionType.LLM_INVOKE, Framework.CUSTOM)
    chain.finalize_last(status=ActionStatus.COMPLETED)

    jsonl = list(tmp_path.glob("*.jsonl"))[0]
    rows = read_receipts(jsonl)
    assert len(rows[0].short_id) == 8


def test_read_receipts_empty_file(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    rows = read_receipts(empty)
    assert rows == []


def test_read_receipts_tolerates_bad_lines(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"valid": true, "receipt_id": "x", "action": {"type": "llm_invoke", "framework": "custom", "status": "completed"}, "timestamp": "2026-01-01T00:00:00+00:00"}\n{not json}\n')
    rows = read_receipts(bad)
    # Bad line skipped, valid line parsed
    assert len(rows) == 1


# ── scan_agents ───────────────────────────────────────────────────────────────

def test_scan_agents_finds_agent(tmp_path):
    identity, chain = make_chain(tmp_path)
    chain.append(ActionType.LLM_INVOKE, Framework.CUSTOM)
    chain.finalize_last(status=ActionStatus.COMPLETED)

    agents = scan_agents(tmp_path)
    assert len(agents) == 1
    assert agents[0].agent_id == identity.agent_id
    assert agents[0].receipt_count == 1
    assert agents[0].chain_valid is True


def test_scan_agents_two_agents(tmp_path):
    for _ in range(2):
        _, chain = make_chain(tmp_path)
        chain.append(ActionType.LLM_INVOKE, Framework.CUSTOM)
        chain.finalize_last(status=ActionStatus.COMPLETED)

    agents = scan_agents(tmp_path)
    assert len(agents) == 2


def test_scan_agents_detects_tampered_chain(tmp_path):
    identity, chain = make_chain(tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="t")
    chain.finalize_last(status=ActionStatus.COMPLETED)

    # Tamper JSONL
    jsonl = list(tmp_path.glob("*.jsonl"))[0]
    lines = jsonl.read_text().strip().splitlines()
    rec = json.loads(lines[0])
    rec["signature"] = "ff" * 64
    jsonl.write_text(json.dumps(rec) + "\n")

    agents = scan_agents(tmp_path)
    assert agents[0].chain_valid is False


def test_scan_agents_empty_dir(tmp_path):
    agents = scan_agents(tmp_path)
    assert agents == []
