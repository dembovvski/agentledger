"""
Tests for AgentLedgerAutoGenHook — AutoGen integration.

Simulates AutoGen ConversableAgent interface without requiring autogen installed:
  - Minimal FakeAgent that implements register_hook / function_map
  - Hook fires in realistic order (messages_before_reply → tool call → message_before_send)
  - Verifies receipts are signed, chained, and CLI-verifiable
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from agentledger.core.chain import ReceiptChainImpl
from agentledger.core.identity import AgentIdentityImpl
from agentledger.integrations.autogen import AgentLedgerAutoGenHook
from agentledger.interfaces import ActionStatus
from tests.conftest import NoopBinding


# ── Fake AutoGen agent ────────────────────────────────────────────────────────

class FakeConversableAgent:
    """Minimal stand-in for autogen.ConversableAgent."""

    def __init__(self, name: str = "assistant"):
        self.name = name
        self._hooks: dict[str, list] = {}
        self.function_map: dict = {}

    def register_hook(self, hook_point: str, fn) -> None:
        self._hooks.setdefault(hook_point, []).append(fn)

    def fire_messages_before_reply(self, messages: list[dict]) -> list[dict]:
        for fn in self._hooks.get("process_all_messages_before_reply", []):
            messages = fn(messages)
        return messages

    def fire_message_before_send(self, message, recipient=None, silent=False):
        for fn in self._hooks.get("process_message_before_send", []):
            message = fn(message, recipient, silent)
        return message

    def call_tool(self, name: str, *args, **kwargs):
        return self.function_map[name](*args, **kwargs)


def make_stack(tmp_path: Path):
    identity = AgentIdentityImpl.create(binding=NoopBinding())
    chain = ReceiptChainImpl(identity, storage_path=str(tmp_path))
    hook = AgentLedgerAutoGenHook(identity=identity, chain=chain)
    return identity, chain, hook


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_autogen_llm_invoke_recorded(tmp_path):
    """LLM invocation: messages_before_reply → message_before_send → 1 receipt."""
    identity, chain, hook = make_stack(tmp_path)
    agent = FakeConversableAgent()
    hook.attach(agent)

    messages = [{"role": "user", "content": "What is 2+2?"}]
    agent.fire_messages_before_reply(messages)
    agent.fire_message_before_send({"role": "assistant", "content": "4"})

    receipts = chain.iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.type.value == "llm_invoke"
    assert receipts[0].action.status == ActionStatus.COMPLETED
    assert chain.verify() is True


def test_autogen_tool_call_recorded(tmp_path):
    """Tool call via function_map is wrapped and recorded."""
    identity, chain, hook = make_stack(tmp_path)
    agent = FakeConversableAgent()
    agent.function_map["calculator"] = lambda x, y: x + y
    hook.attach(agent)

    result = agent.call_tool("calculator", 3, 4)
    assert result == 7

    receipts = chain.iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.type.value == "tool_call"
    assert receipts[0].action.tool_name == "calculator"
    assert receipts[0].action.status == ActionStatus.COMPLETED


def test_autogen_tool_failure_recorded(tmp_path):
    """Tool that raises exception gets FAILED receipt, exception re-raised."""
    identity, chain, hook = make_stack(tmp_path)
    agent = FakeConversableAgent()

    def bad_tool():
        raise ValueError("API timeout")

    agent.function_map["http_get"] = bad_tool
    hook.attach(agent)

    with pytest.raises(ValueError, match="API timeout"):
        agent.call_tool("http_get")

    receipts = chain.iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.status == ActionStatus.FAILED
    assert "API timeout" in receipts[0].action.error


def test_autogen_llm_then_tool(tmp_path):
    """Full flow: LLM decides → tool executes → 2 receipts, chain valid."""
    identity, chain, hook = make_stack(tmp_path)
    agent = FakeConversableAgent()
    agent.function_map["web_search"] = lambda q: f"Results for: {q}"
    hook.attach(agent)

    # LLM invocation
    messages = [{"role": "user", "content": "Search for Python news"}]
    agent.fire_messages_before_reply(messages)
    agent.fire_message_before_send({"role": "assistant", "content": "I'll search for that."})

    # Tool call
    result = agent.call_tool("web_search", "Python news")

    receipts = chain.iter_receipts()
    assert len(receipts) == 2
    assert receipts[0].action.type.value == "llm_invoke"
    assert receipts[1].action.type.value == "tool_call"
    assert receipts[1].action.tool_name == "web_search"
    assert chain.verify() is True


def test_autogen_chain_hash_linkage(tmp_path):
    """prev_hash correctly links receipts across LLM + tool calls."""
    from agentledger.core.receipt import canonicalise_for_signing, sha256_hex

    identity, chain, hook = make_stack(tmp_path)
    agent = FakeConversableAgent()
    agent.function_map["calc"] = lambda x: x * 2
    hook.attach(agent)

    agent.fire_messages_before_reply([{"role": "user", "content": "double 5"}])
    agent.fire_message_before_send("I'll calculate that.")
    agent.call_tool("calc", 5)

    receipts = chain.iter_receipts()
    assert len(receipts) == 2
    expected = sha256_hex(canonicalise_for_signing(receipts[0]))
    assert receipts[1].prev_hash == expected


def test_autogen_cli_verify(tmp_path):
    """Receipts written to JSONL pass CLI verify."""
    from agentledger.cli.verify import verify_receipt_chain

    identity, chain, hook = make_stack(tmp_path)
    agent = FakeConversableAgent()
    agent.function_map["translate"] = lambda t: f"translated: {t}"
    hook.attach(agent)

    agent.fire_messages_before_reply([{"role": "user", "content": "translate hello"}])
    agent.fire_message_before_send("Sure, translating.")
    agent.call_tool("translate", "hello")

    jsonl = list(tmp_path.glob("*.jsonl"))[0]
    ok, msg = verify_receipt_chain(jsonl, agent_public_key=bytes.fromhex(identity.agent_id))
    assert ok is True, msg
    assert "chain valid" in msg


def test_autogen_detach_restores_function_map(tmp_path):
    """detach() unwraps function_map back to originals."""
    identity, chain, hook = make_stack(tmp_path)
    agent = FakeConversableAgent()
    original_fn = lambda x: x + 1
    agent.function_map["inc"] = original_fn
    hook.attach(agent)

    assert agent.function_map["inc"] is not original_fn  # wrapped

    hook.detach(agent)
    assert agent.function_map["inc"] is original_fn  # restored


def test_autogen_no_function_map(tmp_path):
    """Agent without function_map attaches without error (LLM-only agent)."""
    identity, chain, hook = make_stack(tmp_path)
    agent = FakeConversableAgent()
    # function_map is empty dict — attach should not raise
    hook.attach(agent)

    agent.fire_messages_before_reply([{"role": "user", "content": "hello"}])
    agent.fire_message_before_send("hi")

    assert len(chain.iter_receipts()) == 1
