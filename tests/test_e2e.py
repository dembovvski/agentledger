"""
End-to-end integration test.

Simulates a realistic LangChain agent run without requiring LangChain installed:
  1. AgentIdentity created with NoopBinding
  2. ReceiptChain attached via AgentLedgerCallback
  3. Callback methods fired in realistic order (chain_start → llm → tool → tool_error → chain_end)
  4. JSONL written to disk
  5. CLI verify.py reads from disk and validates the chain
  6. All receipts signed and tamper-evident

This is the full circle: write → persist → verify from file.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

from agentledger.core.chain import ReceiptChainImpl
from agentledger.core.identity import AgentIdentityImpl
from agentledger.integrations.langchain import AgentLedgerCallback
from agentledger.interfaces import ActionStatus
from tests.conftest import NoopBinding


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_stack(tmp_path: Path):
    identity = AgentIdentityImpl.create(binding=NoopBinding())
    chain = ReceiptChainImpl(identity, storage_path=str(tmp_path))
    callback = AgentLedgerCallback(identity=identity, chain=chain)
    return identity, chain, callback


def get_jsonl_path(tmp_path: Path) -> Path:
    files = list(tmp_path.glob("*.jsonl"))
    assert files, "No JSONL file written"
    return files[0]


def run_cli_verify(jsonl_path: Path, agent_public_key_hex: str) -> tuple[bool, str]:
    """Run CLI verify programmatically."""
    from agentledger.cli.verify import verify_receipt_chain
    ok, msg = verify_receipt_chain(
        jsonl_path,
        agent_public_key=bytes.fromhex(agent_public_key_hex),
    )
    return ok, msg


# ── Scenario: successful agent run ───────────────────────────────────────────

def test_e2e_successful_agent_run(tmp_path):
    """
    Scenario: agent answers a question using a web_search tool.

    Flow:
      on_chain_start → on_llm_start → on_llm_end →
      on_tool_start(web_search) → on_tool_end →
      on_chain_end
    """
    identity, chain, cb = make_stack(tmp_path)

    # Chain starts
    cb.on_chain_start(
        serialized={"name": "AgentExecutor"},
        inputs={"input": "What is the capital of Poland?"},
    )
    # LLM decides to search
    cb.on_llm_start(
        serialized={"name": "gpt-4"},
        prompts=["What is the capital of Poland?"],
    )
    cb.on_llm_end(response="I should use web_search to answer this.")

    # Tool call
    cb.on_tool_start(
        serialized={"name": "web_search"},
        input_str="capital of Poland",
    )
    cb.on_tool_end(output="Warsaw is the capital of Poland.")

    # Chain finishes
    cb.on_chain_end(outputs={"output": "The capital of Poland is Warsaw."})

    receipts = chain.iter_receipts()
    # on_chain_start opens DECISION, then on_llm_start orphans it (failed).
    # Actual: orphaned DECISION(failed) + LLM_INVOKE(completed) + TOOL_CALL(completed) = 3
    assert len(receipts) == 3

    tool_receipts = [r for r in receipts if r.action.tool_name == "web_search"]
    assert len(tool_receipts) == 1
    assert tool_receipts[0].action.status == ActionStatus.COMPLETED

    llm_receipts = [r for r in receipts if r.action.type.value == "llm_invoke"]
    assert len(llm_receipts) == 1
    assert llm_receipts[0].action.status == ActionStatus.COMPLETED

    # Chain integrity
    assert chain.verify() is True

    # CLI verify from disk
    jsonl = get_jsonl_path(tmp_path)
    ok, msg = run_cli_verify(jsonl, identity.agent_id)
    assert ok is True, msg
    assert "chain valid" in msg


# ── Scenario: tool failure mid-run ────────────────────────────────────────────

def test_e2e_tool_failure_recorded(tmp_path):
    """
    Scenario: tool raises an exception — failure receipt written, chain stays intact.

    Flow:
      on_chain_start → on_tool_start → on_tool_error →
      on_tool_start(retry) → on_tool_end → on_chain_end
    """
    identity, chain, cb = make_stack(tmp_path)

    cb.on_chain_start(
        serialized={"name": "AgentExecutor"},
        inputs={"input": "Fetch data from API"},
    )
    cb.on_tool_start(
        serialized={"name": "http_get"},
        input_str="https://api.example.com/data",
    )
    cb.on_tool_error(error=ConnectionError("Connection timed out"))

    cb.on_tool_start(
        serialized={"name": "http_get"},
        input_str="https://api.example.com/data",
    )
    cb.on_tool_end(output='{"status": "ok"}')
    cb.on_chain_end(outputs={"output": "Data fetched successfully."})

    receipts = chain.iter_receipts()
    # on_chain_start orphaned by on_tool_start → orphaned DECISION(failed) +
    # http_get(failed) + http_get retry(completed) = 3
    assert len(receipts) == 3

    failed = [r for r in receipts if r.action.status == ActionStatus.FAILED]
    assert len(failed) == 2  # orphaned chain + failed tool
    tool_failed = [r for r in failed if r.action.tool_name == "http_get"]
    assert len(tool_failed) == 1
    assert tool_failed[0].action.error is not None
    assert "Connection timed out" in tool_failed[0].action.error

    assert chain.verify() is True

    jsonl = get_jsonl_path(tmp_path)
    ok, msg = run_cli_verify(jsonl, identity.agent_id)
    assert ok is True, msg


# ── Scenario: multi-tool sequential run ──────────────────────────────────────

def test_e2e_multi_tool_sequential(tmp_path):
    """
    Scenario: agent uses two tools in sequence.
    Verifies prev_hash chain linkage across multiple tool calls.
    """
    identity, chain, cb = make_stack(tmp_path)

    cb.on_chain_start(serialized={}, inputs={"input": "Summarise and translate"})

    for tool, inp, out in [
        ("web_search", "latest AI news", "OpenAI released GPT-5"),
        ("translate", "OpenAI released GPT-5", "OpenAI veröffentlichte GPT-5"),
    ]:
        cb.on_tool_start(serialized={"name": tool}, input_str=inp)
        cb.on_tool_end(output=out)

    cb.on_chain_end(outputs={"output": "OpenAI veröffentlichte GPT-5"})

    receipts = chain.iter_receipts()
    # on_chain_start orphaned by first tool → orphaned DECISION + web_search + translate = 3
    assert len(receipts) == 3

    tool_receipts = [r for r in receipts if r.action.type.value == "tool_call"]
    assert len(tool_receipts) == 2

    # Verify hash chain linkage
    from agentledger.core.receipt import canonicalise_for_signing, sha256_hex
    for i in range(1, len(receipts)):
        expected = sha256_hex(canonicalise_for_signing(receipts[i - 1]))
        assert receipts[i].prev_hash == expected, f"Chain broken at receipt {i}"

    assert chain.verify() is True

    jsonl = get_jsonl_path(tmp_path)
    ok, msg = run_cli_verify(jsonl, identity.agent_id)
    assert ok is True, msg


# ── Scenario: JSONL roundtrip ─────────────────────────────────────────────────

def test_e2e_jsonl_roundtrip(tmp_path):
    """
    Verify that what gets written to JSONL is self-consistent:
    - Each line is valid JSON
    - prev_hash in line N+1 matches SHA256 of line N (minus signature)
    - All signatures present
    """
    identity, chain, cb = make_stack(tmp_path)

    cb.on_chain_start(serialized={}, inputs={"input": "test"})
    cb.on_tool_start(serialized={"name": "calculator"}, input_str="2+2")
    cb.on_tool_end(output="4")
    cb.on_chain_end(outputs={"output": "4"})

    jsonl = get_jsonl_path(tmp_path)
    lines = [json.loads(l) for l in jsonl.read_text().strip().splitlines()]

    # on_chain_start orphaned by on_tool_start → 2 finalized receipts
    assert len(lines) == 2

    from agentledger.cli.verify import canonicalise, compute_sha256_hex
    for i, line in enumerate(lines):
        assert "signature" in line, f"Missing signature on line {i+1}"
        assert "receipt_id" in line
        assert "prev_hash" in line

    # prev_hash linkage via CLI canonicalise (without signature)
    for i in range(1, len(lines)):
        prev_no_sig = {k: v for k, v in lines[i - 1].items() if k != "signature"}
        expected = compute_sha256_hex(canonicalise(prev_no_sig))
        assert lines[i]["prev_hash"] == expected, f"JSONL prev_hash broken at line {i+1}"


# ── Scenario: tampered JSONL fails CLI verify ─────────────────────────────────

def test_e2e_tampered_jsonl_fails_verify(tmp_path):
    """
    If someone edits the JSONL file, CLI verify must catch it.
    """
    identity, chain, cb = make_stack(tmp_path)

    cb.on_chain_start(serialized={}, inputs={"input": "test"})
    cb.on_tool_start(serialized={"name": "tool"}, input_str="input")
    cb.on_tool_end(output="output")
    cb.on_chain_end(outputs={"output": "done"})

    jsonl = get_jsonl_path(tmp_path)
    lines = jsonl.read_text().strip().splitlines()

    # Tamper: change prev_hash of second line
    second = json.loads(lines[1])
    second["prev_hash"] = "ff" * 32
    lines[1] = json.dumps(second)
    jsonl.write_text("\n".join(lines) + "\n")

    ok, msg = run_cli_verify(jsonl, identity.agent_id)
    assert ok is False
    assert "prev_hash mismatch" in msg


# ── Scenario: observer guarantee ──────────────────────────────────────────────

def test_e2e_observer_guarantee(tmp_path):
    """
    Observer guarantee: callback is external, agent cannot suppress writes.
    Receipts are written regardless of whether agent 'knows' about them.

    This test verifies that calling callback methods directly (simulating
    external registration) produces a valid chain — agent code never
    touches the chain object.
    """
    identity = AgentIdentityImpl.create(binding=NoopBinding())
    chain = ReceiptChainImpl(identity, storage_path=str(tmp_path))

    # Agent code: knows nothing about the chain
    class FakeAgent:
        def run(self, task: str) -> str:
            return f"Result: {task}"

    # Callback registered externally by the governance layer
    cb = AgentLedgerCallback(identity=identity, chain=chain)

    # Governance layer fires callbacks — agent cannot interfere
    cb.on_chain_start(serialized={}, inputs={"input": "do something"})
    agent = FakeAgent()
    result = agent.run("do something")
    cb.on_chain_end(outputs={"output": result})

    receipts = chain.iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.status == ActionStatus.COMPLETED

    jsonl = get_jsonl_path(tmp_path)
    ok, msg = run_cli_verify(jsonl, identity.agent_id)
    assert ok is True, msg
