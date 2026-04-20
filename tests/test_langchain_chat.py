"""
Tests for on_chat_model_start / on_llm_end / on_llm_error — new handlers added
to fix the orphaned receipt bug (DEAD-11 from code quality audit).
"""

import pytest

langchain = pytest.importorskip(
    "langchain", reason="langchain not installed"
)

from unittest.mock import MagicMock
from agentledger.integrations.langchain import AgentLedgerCallback
from agentledger.interfaces import ActionType, ActionStatus, Framework


@pytest.fixture
def mock_chain():
    chain = MagicMock()
    chain.append.return_value = "receipt-id"
    return chain


@pytest.fixture
def callback(mock_chain):
    ident = MagicMock()
    ident.agent_id = "deadbeef" * 8
    return AgentLedgerCallback(identity=ident, chain=mock_chain)


class TestOnChatModelEvents:

    def test_on_chat_model_start_appends_llm_invoke(self, callback, mock_chain):
        callback.on_chat_model_start(
            serialized={}, messages=[[MagicMock(content="hello")]]
        )
        mock_chain.append.assert_called_once()
        assert mock_chain.append.call_args.kwargs["action_type"] == ActionType.LLM_INVOKE
        assert mock_chain.append.call_args.kwargs["tool_name"] == "chat"

    def test_on_llm_end_finalizes_completed(self, callback, mock_chain):
        callback.on_chat_model_start(serialized={}, messages=[[]])
        callback.on_llm_end(response="the answer")
        mock_chain.finalize_last.assert_called_once()
        assert mock_chain.finalize_last.call_args.kwargs["status"] == ActionStatus.COMPLETED

    def test_on_llm_error_finalizes_failed(self, callback, mock_chain):
        callback.on_chat_model_start(serialized={}, messages=[[]])
        callback.on_llm_error(error=RuntimeError("model timeout"))
        mock_chain.finalize_last.assert_called_once()
        kw = mock_chain.finalize_last.call_args.kwargs
        assert kw["status"] == ActionStatus.FAILED
        assert "RuntimeError" in kw["error"]

    def test_on_llm_end_without_prior_start_does_not_raise(self, callback, mock_chain):
        callback.on_llm_end(response="unexpected")
        mock_chain.finalize_last.assert_called_once()

    def test_chat_model_start_includes_message_content(self, callback, mock_chain):
        msg = MagicMock()
        msg.__str__ = lambda self: "user: test message"
        callback.on_chat_model_start(serialized={}, messages=[[msg]])
        payload = mock_chain.append.call_args.kwargs["payload"]
        assert "user: test message" in payload
