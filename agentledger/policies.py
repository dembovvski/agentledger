"""
Built-in ActionPolicy implementations for AgentLedger pre-execution gate.

Usage:
    from agentledger.policies import DenylistPolicy, AllowlistPolicy, HumanApprovalPolicy

    chain = ReceiptChainImpl(identity, storage_path="...", policy=DenylistPolicy(["rm_rf", "exec"]))
"""

from __future__ import annotations

from typing import Callable, Optional

from agentledger.interfaces import (
    ActionPolicy,
    ActionType,
    PolicyResult,
    PolicyVerdict,
)


class AllowAllPolicy(ActionPolicy):
    """Allows every action. Equivalent to no policy (the default)."""

    def evaluate(self, action_type: ActionType, tool_name: Optional[str], payload: Optional[str]) -> PolicyResult:
        return PolicyResult(verdict=PolicyVerdict.ALLOW)


class DenylistPolicy(ActionPolicy):
    """
    Blocks specific tool names. All other actions pass through.

    Example:
        DenylistPolicy(["rm_rf", "exec_shell", "send_email"])
    """

    def __init__(self, denied_tools: list[str]) -> None:
        self._denied = set(denied_tools)

    def evaluate(self, action_type: ActionType, tool_name: Optional[str], payload: Optional[str]) -> PolicyResult:
        # tool_name=None cannot match any denylist entry — passes through.
        # TOOL_CALL with no name is rejected earlier by chain.append() validation.
        if tool_name in self._denied:
            return PolicyResult(
                verdict=PolicyVerdict.DENY,
                reason=f"tool '{tool_name}' is on the denylist",
            )
        return PolicyResult(verdict=PolicyVerdict.ALLOW)


class AllowlistPolicy(ActionPolicy):
    """
    Only permits specific tool names. Everything else is denied.
    LLM_INVOKE and DECISION actions are always allowed (not tool calls).

    Example:
        AllowlistPolicy(["web_search", "calculator"])
    """

    def __init__(self, allowed_tools: list[str]) -> None:
        self._allowed = set(allowed_tools)

    def evaluate(self, action_type: ActionType, tool_name: Optional[str], payload: Optional[str]) -> PolicyResult:
        if action_type != ActionType.TOOL_CALL:
            return PolicyResult(verdict=PolicyVerdict.ALLOW)
        if tool_name in self._allowed:
            return PolicyResult(verdict=PolicyVerdict.ALLOW)
        return PolicyResult(
            verdict=PolicyVerdict.DENY,
            reason=f"tool '{tool_name}' is not on the allowlist",
        )


class HumanApprovalPolicy(ActionPolicy):
    """
    Human-in-the-loop gate: prompts for approval before each action.

    By default uses built-in input(). Inject a custom prompt_fn for
    testing or async environments.

    Example:
        policy = HumanApprovalPolicy()
        # or: HumanApprovalPolicy(prompt_fn=my_slack_approval_fn)
    """

    def __init__(self, prompt_fn: Optional[Callable[[str], str]] = None) -> None:
        self._prompt = prompt_fn or self._default_prompt

    @staticmethod
    def _default_prompt(message: str) -> str:
        return input(message)

    def evaluate(self, action_type: ActionType, tool_name: Optional[str], payload: Optional[str]) -> PolicyResult:
        label = tool_name or action_type.value
        answer = self._prompt(f"[AgentLedger] Approve '{label}'? [y/N] ").strip().lower()
        if answer in ("y", "yes"):
            return PolicyResult(verdict=PolicyVerdict.ALLOW)
        return PolicyResult(
            verdict=PolicyVerdict.DENY,
            reason="human operator denied",
        )


class CompositePolicy(ActionPolicy):
    """
    Chains multiple policies: first DENY wins, otherwise ALLOW.

    Example:
        CompositePolicy([DenylistPolicy(["rm_rf"]), AllowlistPolicy(["search"])])
    """

    def __init__(self, policies: list[ActionPolicy]) -> None:
        self._policies = policies

    def evaluate(self, action_type: ActionType, tool_name: Optional[str], payload: Optional[str]) -> PolicyResult:
        for policy in self._policies:
            result = policy.evaluate(action_type, tool_name, payload)
            if result.verdict == PolicyVerdict.DENY:
                return result
        return PolicyResult(verdict=PolicyVerdict.ALLOW)
