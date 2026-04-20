"""
AgentLedgerAutoGenHook — AutoGen integration for audit trail.

Usage:
    from agentledger.integrations.autogen import AgentLedgerAutoGenHook

    hook = AgentLedgerAutoGenHook(identity=identity, chain=chain)
    hook.attach(agent)  # ConversableAgent

The hook registers on the agent externally — the agent cannot suppress it.
Tool calls are wrapped transparently via function_map patching.
"""

from __future__ import annotations

import json
from typing import Any

from agentledger.interfaces import (
    AgentIdentity,
    ReceiptChain,
    ActionType,
    ActionStatus,
    Framework,
)


class AgentLedgerAutoGenHook:
    """
    AutoGen hook that records every LLM invocation and tool call as a
    signed receipt in the agent's append-only chain.

    Attach to any ConversableAgent via ``attach(agent)``.
    The agent object is not modified beyond hook registration and
    function_map wrapping — both are reversible.
    """

    def __init__(self, identity: AgentIdentity, chain: ReceiptChain) -> None:
        self.identity = identity
        self.chain = chain
        self._wrapped_functions: dict[str, Any] = {}

    def attach(self, agent: Any) -> None:
        """
        Register hooks and wrap tool functions on a ConversableAgent.

        Args:
            agent: autogen.ConversableAgent (or subclass)
        """
        agent.register_hook(
            "process_all_messages_before_reply",
            self._on_messages_before_reply,
        )
        agent.register_hook(
            "process_message_before_send",
            self._on_message_before_send,
        )
        self._wrap_function_map(agent)

    # ── LLM hooks ─────────────────────────────────────────────────────────────

    def _on_messages_before_reply(self, messages: list[dict]) -> list[dict]:
        """
        Fired before the agent calls the LLM to generate a reply.
        Records an LLM_INVOKE receipt (pending until reply is sent).
        """
        payload = json.dumps(messages, ensure_ascii=False, default=str)
        self.chain.append(
            action_type=ActionType.LLM_INVOKE,
            framework=Framework.AUTOGEN,
            payload=payload,
        )
        return messages

    def _on_message_before_send(self, message: dict | str, recipient: Any, silent: bool) -> dict | str:
        """
        Fired after the LLM generates a reply, before it is sent.
        Finalises the pending LLM_INVOKE receipt.
        """
        result = json.dumps(message, ensure_ascii=False, default=str) if isinstance(message, dict) else str(message)
        self.chain.finalize_last(status=ActionStatus.COMPLETED, result=result)
        return message

    # ── Tool wrapping ──────────────────────────────────────────────────────────

    def _wrap_function_map(self, agent: Any) -> None:
        """
        Wraps each function in agent.function_map so tool calls are recorded.
        Skips agents that have no function_map.
        """
        function_map: dict[str, Any] | None = getattr(agent, "function_map", None)
        if not function_map:
            return

        for name, fn in list(function_map.items()):
            if name not in self._wrapped_functions:
                function_map[name] = self._make_wrapper(name, fn)
                self._wrapped_functions[name] = fn  # keep original for detach

    def _make_wrapper(self, tool_name: str, fn: Any):
        """Returns an instrumented wrapper around a tool function."""
        chain = self.chain

        def wrapper(*args, **kwargs):
            payload = json.dumps({"args": args, "kwargs": kwargs}, ensure_ascii=False, default=str)
            chain.append(
                action_type=ActionType.TOOL_CALL,
                framework=Framework.AUTOGEN,
                tool_name=tool_name,
                payload=payload,
            )
            try:
                result = fn(*args, **kwargs)
                chain.finalize_last(
                    status=ActionStatus.COMPLETED,
                    result=str(result),
                )
                return result
            except Exception as exc:
                chain.finalize_last(
                    status=ActionStatus.FAILED,
                    error=str(exc),
                )
                raise

        wrapper.__name__ = fn.__name__ if hasattr(fn, "__name__") else tool_name
        return wrapper

    def detach(self, agent: Any) -> None:
        """
        Restore original function_map entries (unwrap).
        Hook deregistration is not supported by AutoGen — hooks remain.
        """
        function_map: dict[str, Any] | None = getattr(agent, "function_map", None)
        if function_map:
            for name, original in self._wrapped_functions.items():
                if name in function_map:
                    function_map[name] = original
        self._wrapped_functions.clear()
