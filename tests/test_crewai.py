"""
Tests for AgentLedgerCrewCallback — CrewAI integration.

Simulates CrewAI interface without requiring crewai installed:
  - FakeBaseTool with _run()
  - FakeAgentAction / FakeAgentFinish / FakeTaskOutput
  - Verifies step_callback, task_callback, wrap_tool, wrap_tools
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentledger.core.chain import ReceiptChainImpl
from agentledger.core.identity import AgentIdentityImpl
from agentledger.integrations.crewai import AgentLedgerCrewCallback
from agentledger.interfaces import ActionStatus
from tests.conftest import NoopBinding


# ── Fake CrewAI types ─────────────────────────────────────────────────────────

class FakeBaseTool:
    def __init__(self, name: str, fn):
        self.name = name
        self._fn = fn

    def _run(self, *args, **kwargs):
        return self._fn(*args, **kwargs)


class FakeAgentAction:
    def __init__(self, tool: str, tool_input: str, log: str = ""):
        self.tool = tool
        self.tool_input = tool_input
        self.log = log


class FakeAgentFinish:
    def __init__(self, return_values: dict):
        self.return_values = return_values


class FakeTaskOutput:
    def __init__(self, raw: str):
        self.raw = raw


def make_stack(tmp_path: Path):
    identity = AgentIdentityImpl.create(binding=NoopBinding())
    chain = ReceiptChainImpl(identity, storage_path=str(tmp_path))
    cb = AgentLedgerCrewCallback(identity=identity, chain=chain)
    return identity, chain, cb


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_crewai_agent_action_step(tmp_path):
    """step_callback with AgentAction records DECISION receipt."""
    identity, chain, cb = make_stack(tmp_path)

    action = FakeAgentAction(tool="web_search", tool_input="latest AI news")
    cb.step_callback(action)

    receipts = chain.iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.type.value == "decision"
    assert receipts[0].action.tool_name == "web_search"
    assert receipts[0].action.status == ActionStatus.COMPLETED


def test_crewai_agent_finish_step(tmp_path):
    """step_callback with AgentFinish records completed DECISION."""
    identity, chain, cb = make_stack(tmp_path)

    finish = FakeAgentFinish(return_values={"output": "Warsaw is the capital of Poland."})
    cb.step_callback(finish)

    receipts = chain.iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.tool_name == "agent_finish"
    assert receipts[0].action.status == ActionStatus.COMPLETED


def test_crewai_task_callback(tmp_path):
    """task_callback records task completion receipt."""
    identity, chain, cb = make_stack(tmp_path)

    task_output = FakeTaskOutput(raw="Research complete: 5 sources found.")
    cb.task_callback(task_output)

    receipts = chain.iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.tool_name == "task_complete"
    assert receipts[0].action.status == ActionStatus.COMPLETED


def test_crewai_wrap_tool_success(tmp_path):
    """Wrapped BaseTool._run() records TOOL_CALL receipt on success."""
    identity, chain, cb = make_stack(tmp_path)

    tool = FakeBaseTool("calculator", lambda x, y: x + y)
    cb.wrap_tool(tool)

    result = tool._run(3, 4)
    assert result == 7

    receipts = chain.iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.type.value == "tool_call"
    assert receipts[0].action.tool_name == "calculator"
    assert receipts[0].action.status == ActionStatus.COMPLETED


def test_crewai_wrap_tool_failure(tmp_path):
    """Wrapped tool that raises records FAILED receipt and re-raises."""
    identity, chain, cb = make_stack(tmp_path)

    def broken(_):
        raise RuntimeError("rate limit exceeded")

    tool = FakeBaseTool("api_tool", broken)
    cb.wrap_tool(tool)

    with pytest.raises(RuntimeError, match="rate limit exceeded"):
        tool._run("query")

    receipts = chain.iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.status == ActionStatus.FAILED
    assert "rate limit exceeded" in receipts[0].action.error


def test_crewai_wrap_callable(tmp_path):
    """Plain callable wrapped via wrap_tool records TOOL_CALL."""
    identity, chain, cb = make_stack(tmp_path)

    def translate(text: str) -> str:
        return f"[translated] {text}"

    wrapped = cb.wrap_tool(translate)
    result = wrapped("hello")
    assert result == "[translated] hello"

    receipts = chain.iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.tool_name == "translate"
    assert receipts[0].action.status == ActionStatus.COMPLETED


def test_crewai_wrap_tools_list(tmp_path):
    """wrap_tools wraps all tools in a list."""
    identity, chain, cb = make_stack(tmp_path)

    tools = [
        FakeBaseTool("search", lambda q: f"results: {q}"),
        FakeBaseTool("summarise", lambda t: f"summary: {t}"),
    ]
    wrapped = cb.wrap_tools(tools)

    wrapped[0]._run("AI news")
    wrapped[1]._run("long text")

    receipts = chain.iter_receipts()
    assert len(receipts) == 2
    assert receipts[0].action.tool_name == "search"
    assert receipts[1].action.tool_name == "summarise"


def test_crewai_full_flow_chain_valid(tmp_path):
    """Full agent run: step → tool → task → chain valid + CLI verifiable."""
    from agentledger.cli.verify import verify_receipt_chain

    identity, chain, cb = make_stack(tmp_path)

    tool = FakeBaseTool("web_search", lambda q: f"results for {q}")
    cb.wrap_tool(tool)

    # Agent decides to use tool
    cb.step_callback(FakeAgentAction("web_search", "capital of Poland"))
    # Tool executes
    tool._run("capital of Poland")
    # Agent finishes
    cb.step_callback(FakeAgentFinish({"output": "Warsaw"}))
    # Task completes
    cb.task_callback(FakeTaskOutput("Warsaw is the capital of Poland."))

    assert chain.verify() is True

    jsonl = list(tmp_path.glob("*.jsonl"))[0]
    ok, msg = verify_receipt_chain(jsonl, agent_public_key=bytes.fromhex(identity.agent_id))
    assert ok is True, msg
    assert "chain valid" in msg


def test_crewai_hash_chain_linkage(tmp_path):
    """prev_hash correctly links all receipts in a multi-step run."""
    from agentledger.core.receipt import canonicalise_for_signing, sha256_hex

    identity, chain, cb = make_stack(tmp_path)
    tool = FakeBaseTool("calc", lambda x: x * 10)
    cb.wrap_tool(tool)

    cb.step_callback(FakeAgentAction("calc", "5"))
    tool._run(5)
    cb.step_callback(FakeAgentFinish({"output": "50"}))

    receipts = chain.iter_receipts()
    assert len(receipts) == 3
    for i in range(1, len(receipts)):
        expected = sha256_hex(canonicalise_for_signing(receipts[i - 1]))
        assert receipts[i].prev_hash == expected, f"Chain broken at receipt {i}"
