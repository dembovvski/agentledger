"""
Tests for AgentLedgerCallback — LangChain callback handler.

Tests the callback methods in isolation by patching the chain.
LangChain itself is an optional extra: pip install agentledger[langchain]
If langchain is not installed, all tests are skipped.
"""

import pytest

langchain = pytest.importorskip(
    "langchain", reason="langchain not installed — pip install agentledger[langchain]"
)

from unittest.mock import MagicMock, patch
from agentledger.integrations.langchain import AgentLedgerCallback
from agentledger.interfaces import ActionType, ActionStatus, Framework


@pytest.fixture
def mock_identity():
    ident = MagicMock()
    ident.agent_id = "test-agent-id-32byteshexxxx"
    ident.principal_id = "test-principal"
    return ident


@pytest.fixture
def mock_chain():
    chain = MagicMock()
    chain.append.return_value = "receipt-uuid-1"
    return chain


@pytest.fixture
def callback(mock_identity, mock_chain):
    return AgentLedgerCallback(identity=mock_identity, chain=mock_chain)


class TestOnToolEvents:
    """on_tool_start / on_tool_end / on_tool_error create and finalise receipts."""

    def test_on_tool_start_calls_append(self, callback, mock_chain):
        callback.on_tool_start(serialized={"name": "search"}, input_str="query")
        mock_chain.append.assert_called_once()
        call_kwargs = mock_chain.append.call_args.kwargs
        assert call_kwargs["action_type"] == ActionType.TOOL_CALL
        assert call_kwargs["framework"] == Framework.LANGCHAIN
        assert call_kwargs["tool_name"] == "search"
        assert call_kwargs["payload"] == "query"

    def test_on_tool_end_finalizes_with_completed(self, callback, mock_chain):
        callback.on_tool_start(serialized={"name": "search"}, input_str="query")
        callback.on_tool_end(output="result")
        mock_chain.finalize_last.assert_called_once()
        call_kwargs = mock_chain.finalize_last.call_args.kwargs
        assert call_kwargs["status"] == ActionStatus.COMPLETED
        assert call_kwargs["result"] == "result"

    def test_on_tool_error_finalizes_with_failed(self, callback, mock_chain):
        callback.on_tool_start(serialized={"name": "search"}, input_str="query")
        callback.on_tool_error(error=RuntimeError("search failed"))
        mock_chain.finalize_last.assert_called_once()
        call_kwargs = mock_chain.finalize_last.call_args.kwargs
        assert call_kwargs["status"] == ActionStatus.FAILED
        assert "RuntimeError" in call_kwargs["error"]


class TestOnLLMEvents:
    """on_llm_start / on_llm_end / on_llm_error handle LLM invocations."""

    def test_on_llm_start_string_prompt(self, callback, mock_chain):
        callback.on_llm_start(serialized={}, prompts="hello")
        mock_chain.append.assert_called_once()
        assert mock_chain.append.call_args.kwargs["action_type"] == ActionType.LLM_INVOKE
        assert mock_chain.append.call_args.kwargs["payload"] == "hello"

    def test_on_llm_start_list_prompts(self, callback, mock_chain):
        callback.on_llm_start(serialized={}, prompts=["prompt1", "prompt2"])
        mock_chain.append.assert_called_once()
        assert "prompt1" in mock_chain.append.call_args.kwargs["payload"]
        assert "prompt2" in mock_chain.append.call_args.kwargs["payload"]

    def test_on_llm_end_with_response(self, callback, mock_chain):
        callback.on_llm_start(serialized={}, prompts="prompt")
        callback.on_llm_end(response="llm output")
        call_kwargs = mock_chain.finalize_last.call_args.kwargs
        assert call_kwargs["status"] == ActionStatus.COMPLETED

    def test_on_llm_error_finalizes_with_failed(self, callback, mock_chain):
        callback.on_llm_start(serialized={}, prompts="prompt")
        callback.on_llm_error(error=ValueError("model down"))
        call_kwargs = mock_chain.finalize_last.call_args.kwargs
        assert call_kwargs["status"] == ActionStatus.FAILED
        assert "ValueError" in call_kwargs["error"]


class TestOnAgentActionDoesNotCreateOrphanReceipt:
    """
    on_agent_action must NOT create a pending receipt without finalising it.

    Previously this called chain.append() directly, leaving an orphan pending
    receipt that would be force-failed on the next append(). The fix: on_agent_action
    is a no-op (pass), because the agent's decision is already captured by
    on_chain_start as a PENDING DECISION receipt.
    """

    def test_on_agent_action_does_not_append(self, callback, mock_chain):
        callback.on_agent_action(action=MagicMock())
        mock_chain.append.assert_not_called()

    def test_on_agent_action_does_not_finalize(self, callback, mock_chain):
        callback.on_agent_action(action=MagicMock())
        mock_chain.finalize_last.assert_not_called()


class TestOnChainEvents:
    """on_chain_start / on_chain_end / on_chain_error manage top-level receipts."""

    def test_on_chain_start_creates_decision_receipt(self, callback, mock_chain):
        callback.on_chain_start(serialized={}, inputs={"input": "data"})
        mock_chain.append.assert_called_once()
        assert mock_chain.append.call_args.kwargs["action_type"] == ActionType.DECISION
        assert mock_chain.append.call_args.kwargs["tool_name"] == "chain"

    def test_on_chain_end_finalizes_with_completed(self, callback, mock_chain):
        callback.on_chain_start(serialized={}, inputs={})
        callback.on_chain_end(outputs={"result": "done"})
        call_kwargs = mock_chain.finalize_last.call_args.kwargs
        assert call_kwargs["status"] == ActionStatus.COMPLETED

    def test_on_chain_error_finalizes_with_failed(self, callback, mock_chain):
        callback.on_chain_start(serialized={}, inputs={})
        callback.on_chain_error(error=RuntimeError("chain crashed"))
        call_kwargs = mock_chain.finalize_last.call_args.kwargs
        assert call_kwargs["status"] == ActionStatus.FAILED


class TestOnRetrieverEvents:
    """on_retriever_start / on_retriever_end / on_retriever_error."""

    def test_on_retriever_start_appends(self, callback, mock_chain):
        callback.on_retriever_start(query="test query")
        mock_chain.append.assert_called_once()
        assert mock_chain.append.call_args.kwargs["tool_name"] == "retriever"

    def test_on_retriever_end_finalizes(self, callback, mock_chain):
        callback.on_retriever_start(query="test")
        callback.on_retriever_end(query="test", documents=["doc1"])
        call_kwargs = mock_chain.finalize_last.call_args.kwargs
        assert call_kwargs["status"] == ActionStatus.COMPLETED


class TestOnText:
    """on_text logs low-priority text events as DECISION receipts."""

    def test_on_text_appends_decision(self, callback, mock_chain):
        callback.on_text(text="intermediate thought")
        mock_chain.append.assert_called_once()
        assert mock_chain.append.call_args.kwargs["action_type"] == ActionType.DECISION
        assert mock_chain.append.call_args.kwargs["tool_name"] == "text"
