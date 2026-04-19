"""
AgentLedgerCallback — LangChain callback handler for audit trail.

Usage:
    from agentledger.integrations.langchain import AgentLedgerCallback

    callback = AgentLedgerCallback(identity=identity, chain=chain)
    agent = initialize_agent(..., callbacks=[callback])

Callback is registered externally — agent cannot suppress it or modify
receipts after they are written.
"""

from __future__ import annotations

from typing import Any, Optional, TYPE_CHECKING

from agentledger.interfaces import (
    AgentIdentity,
    ReceiptChain,
    ActionType,
    ActionStatus,
    Framework,
)

if TYPE_CHECKING:
    from langchain.callbacks.base import BaseCallbackHandler


class AgentLedgerCallback:
    """
    LangChain callback handler that records every LLM invocation,
    tool call, and agent decision as a signed receipt in the agent's
    append-only chain.

    Thread-safety: ``ReceiptChain.finalize_last`` is thread-safe by contract.
    If the agent dispatches multiple tool calls concurrently, each
    completing thread calls ``on_tool_end`` independently — the chain
    handles serialization internally.
    """

    def __init__(
        self,
        identity: AgentIdentity,
        chain: ReceiptChain,
    ) -> None:
        """
        Args:
            identity: This agent's identity (Ed25519 keypair + binding).
            chain: ReceiptChain instance for this agent.
        """
        self.identity = identity
        self.chain = chain

    # ─── Tool events ───────────────────────────────────────────────────────────

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """
        Called when a tool is about to execute.
        Creates a PENDING receipt with payload_hash set.
        """
        tool_name = serialized.get("name") if isinstance(serialized, dict) else None
        self.chain.append(
            action_type=ActionType.TOOL_CALL,
            framework=Framework.LANGCHAIN,
            tool_name=tool_name,
            payload=input_str,
        )

    def on_tool_end(
        self,
        output: str,
        **kwargs: Any,
    ) -> None:
        """
        Called when a tool finishes successfully.
        Finalises the pending receipt with status=completed and result_hash.
        """
        self.chain.finalize_last(status=ActionStatus.COMPLETED, result=output)

    def on_tool_error(
        self,
        error: BaseException,
        **kwargs: Any,
    ) -> None:
        """
        Called when a tool raises an exception.
        Finalises the pending receipt with status=failed and error message.
        """
        self.chain.finalize_last(
            status=ActionStatus.FAILED,
            error=str(error),
        )

    # ─── LLM events ────────────────────────────────────────────────────────────

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str] | str,
        **kwargs: Any,
    ) -> None:
        """
        Called before an LLM is invoked.
        For chat models, prompts is a list of message dicts.
        We store the serialised prompts as payload.
        """
        payload = prompts if isinstance(prompts, str) else "\n".join(str(p) for p in prompts)
        self.chain.append(
            action_type=ActionType.LLM_INVOKE,
            framework=Framework.LANGCHAIN,
            payload=payload,
        )

    def on_llm_end(
        self,
        response: Any,
        **kwargs: Any,
    ) -> None:
        """
        Called when an LLM finishes generating a response.
        Finalises pending receipt with status=completed.
        """
        # LangChain LLM end response type varies — serialise to string for hash
        result = str(response) if response is not None else ""
        self.chain.finalize_last(status=ActionStatus.COMPLETED, result=result)

    def on_llm_error(
        self,
        error: BaseException,
        **kwargs: Any,
    ) -> None:
        """
        Called when an LLM invocation fails.
        Finalises pending receipt with status=failed.
        """
        self.chain.finalize_last(status=ActionStatus.FAILED, error=str(error))

    # ─── Agent decision events ─────────────────────────────────────────────────

    def on_agent_action(
        self,
        action: Any,
        **kwargs: Any,
    ) -> None:
        """
        Called when an agent takes an action (e.g. a reasoning step).
        Decision is already captured by on_chain_start — do NOT create
        another pending receipt here (would become orphaned before tool exec).
        """
        pass

    def on_agent_finish(
        self,
        finish: Any,
        **kwargs: Any,
    ) -> None:
        """
        Called when an agent completes successfully.
        Finalises the pending receipt with status=completed.
        """
        result = str(finish) if finish is not None else ""
        self.chain.finalize_last(status=ActionStatus.COMPLETED, result=result)

    def on_agent_error(
        self,
        error: BaseException,
        **kwargs: Any,
    ) -> None:
        """
        Called when an agent run fails.
        Finalises the pending receipt with status=failed.
        """
        self.chain.finalize_last(status=ActionStatus.FAILED, error=str(error))

    # ─── Chain events ──────────────────────────────────────────────────────────

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """
        Called when a chain (agent + tools) starts.
        Creates a top-level decision receipt for the run.
        """
        self.chain.append(
            action_type=ActionType.DECISION,
            framework=Framework.LANGCHAIN,
            tool_name="chain",
            payload=str(inputs),
        )

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """
        Called when a chain completes.
        Finalises the pending receipt.
        """
        result = str(outputs) if outputs is not None else ""
        self.chain.finalize_last(status=ActionStatus.COMPLETED, result=result)

    def on_chain_error(
        self,
        error: BaseException,
        **kwargs: Any,
    ) -> None:
        """
        Called when a chain run fails.
        Finalises the pending receipt with status=failed.
        """
        self.chain.finalize_last(status=ActionStatus.FAILED, error=str(error))

    # ─── Retriever events ──────────────────────────────────────────────────────

    def on_retriever_start(
        self,
        query: str,
        **kwargs: Any,
    ) -> None:
        """Called when a retriever is invoked."""
        self.chain.append(
            action_type=ActionType.TOOL_CALL,
            framework=Framework.LANGCHAIN,
            tool_name="retriever",
            payload=query,
        )

    def on_retriever_end(
        self,
        query: str,
        documents: Any,
        **kwargs: Any,
    ) -> None:
        """Called when a retriever finishes."""
        result = str(documents) if documents is not None else ""
        self.chain.finalize_last(status=ActionStatus.COMPLETED, result=result)

    def on_retriever_error(
        self,
        error: BaseException,
        **kwargs: Any,
    ) -> None:
        """Called when a retriever fails."""
        self.chain.finalize_last(status=ActionStatus.FAILED, error=str(error))

    # ─── Text/chat events ──────────────────────────────────────────────────────

    def on_text(
        self,
        text: str,
        **kwargs: Any,
    ) -> None:
        """
        Called on text logs generated during execution.
        Immediately finalised — avoids orphaned pending receipt before
        the next on_tool_start / on_llm_start call.
        """
        self.chain.append(
            action_type=ActionType.DECISION,
            framework=Framework.LANGCHAIN,
            tool_name="text",
            payload=text,
        )
        self.chain.finalize_last(status=ActionStatus.COMPLETED, result=text)

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        **kwargs: Any,
    ) -> None:
        """
        Called before a chat model is invoked.
        messages: list of message lists (one per input).
        """
        payload = "\n".join(str(m) for batch in messages for m in batch)
        self.chain.append(
            action_type=ActionType.LLM_INVOKE,
            framework=Framework.LANGCHAIN,
            tool_name="chat",
            payload=payload,
        )
