"""
AgentLedgerCrewCallback — CrewAI integration for audit trail.

Usage:
    from agentledger.integrations.crewai import AgentLedgerCrewCallback

    cb = AgentLedgerCrewCallback(identity=identity, chain=chain)

    # Wrap tools before passing to agents
    audited_tools = cb.wrap_tools([search_tool, calculator_tool])

    crew = Crew(
        agents=[agent],
        tasks=[task],
        step_callback=cb.step_callback,
        task_callback=cb.task_callback,
    )

step_callback fires after each agent reasoning step (AgentAction / AgentFinish).
task_callback fires after each Task completes.
Tools are wrapped to record TOOL_CALL receipts on every _run() invocation.
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


class AgentLedgerCrewCallback:
    """
    CrewAI callback handler that records agent steps and tool calls as
    signed receipts in the agent's append-only chain.

    Register via Crew(step_callback=cb.step_callback, task_callback=cb.task_callback)
    and wrap tools with cb.wrap_tools(tools) before assigning to agents.
    """

    def __init__(self, identity: AgentIdentity, chain: ReceiptChain) -> None:
        self.identity = identity
        self.chain = chain

    # ── Crew-level callbacks ───────────────────────────────────────────────────

    def step_callback(self, output: Any) -> None:
        """
        Fires after each agent reasoning step.

        CrewAI passes either:
          - AgentAction  (tool call step): .tool, .tool_input, .log
          - AgentFinish  (final answer):   .return_values, .log
        Both are duck-typed so this works without LangChain installed.
        """
        if hasattr(output, "tool") and hasattr(output, "tool_input"):
            # AgentAction — tool invocation step (tool wrapping handles receipt)
            # Record the decision to use this tool
            payload = json.dumps(
                {"tool": output.tool, "input": output.tool_input, "log": getattr(output, "log", "")},
                ensure_ascii=False,
                default=str,
            )
            self.chain.append(
                action_type=ActionType.DECISION,
                framework=Framework.CREWAI,
                tool_name=str(output.tool),
                payload=payload,
            )
            self.chain.finalize_last(status=ActionStatus.COMPLETED, result=payload)

        elif hasattr(output, "return_values"):
            # AgentFinish — agent completed its reasoning
            result = json.dumps(output.return_values, ensure_ascii=False, default=str)
            self.chain.append(
                action_type=ActionType.DECISION,
                framework=Framework.CREWAI,
                tool_name="agent_finish",
                payload=result,
            )
            self.chain.finalize_last(status=ActionStatus.COMPLETED, result=result)

        else:
            # Unknown step type — record as generic decision
            payload = str(output)
            self.chain.append(
                action_type=ActionType.DECISION,
                framework=Framework.CREWAI,
                payload=payload,
            )
            self.chain.finalize_last(status=ActionStatus.COMPLETED, result=payload)

    def task_callback(self, output: Any) -> None:
        """
        Fires after each Task completes.
        TaskOutput has .raw (str) and optionally .pydantic / .json_dict.
        """
        result = getattr(output, "raw", str(output))
        self.chain.append(
            action_type=ActionType.DECISION,
            framework=Framework.CREWAI,
            tool_name="task_complete",
            payload=result,
        )
        self.chain.finalize_last(status=ActionStatus.COMPLETED, result=result)

    # ── Tool wrapping ──────────────────────────────────────────────────────────

    def wrap_tools(self, tools: list[Any]) -> list[Any]:
        """Wrap a list of BaseTool instances. Returns wrapped copies."""
        return [self.wrap_tool(t) for t in tools]

    def wrap_tool(self, tool: Any) -> Any:
        """
        Wrap a single BaseTool (or callable) so _run() is audited.

        For BaseTool subclasses: patches _run in-place and returns the tool.
        For plain callables: returns a wrapper function.
        """
        if callable(tool) and not hasattr(tool, "_run"):
            return self._wrap_callable(tool)
        return self._wrap_base_tool(tool)

    def _wrap_base_tool(self, tool: Any) -> Any:
        """Patch _run on a BaseTool instance."""
        original_run = tool._run
        chain = self.chain
        tool_name = getattr(tool, "name", type(tool).__name__)

        def audited_run(*args, **kwargs):
            payload = json.dumps({"args": args, "kwargs": kwargs}, ensure_ascii=False, default=str)
            chain.append(
                action_type=ActionType.TOOL_CALL,
                framework=Framework.CREWAI,
                tool_name=tool_name,
                payload=payload,
            )
            try:
                result = original_run(*args, **kwargs)
                chain.finalize_last(status=ActionStatus.COMPLETED, result=str(result))
                return result
            except Exception as exc:
                chain.finalize_last(status=ActionStatus.FAILED, error=str(exc))
                raise

        tool._run = audited_run
        return tool

    def _wrap_callable(self, fn: Any) -> Any:
        """Wrap a plain callable (e.g. @tool decorated function)."""
        chain = self.chain
        tool_name = getattr(fn, "__name__", "unknown_tool")

        def wrapper(*args, **kwargs):
            payload = json.dumps({"args": args, "kwargs": kwargs}, ensure_ascii=False, default=str)
            chain.append(
                action_type=ActionType.TOOL_CALL,
                framework=Framework.CREWAI,
                tool_name=tool_name,
                payload=payload,
            )
            try:
                result = fn(*args, **kwargs)
                chain.finalize_last(status=ActionStatus.COMPLETED, result=str(result))
                return result
            except Exception as exc:
                chain.finalize_last(status=ActionStatus.FAILED, error=str(exc))
                raise

        wrapper.__name__ = tool_name
        return wrapper
