"""Tests for ReceiptChainImpl — append, finalize, verify, thread-safety."""

import json
import threading
import tempfile
from pathlib import Path

import pytest
from agentledger.core.chain import ReceiptChainImpl
from agentledger.core.receipt import canonicalise_for_signing, sha256_hex
from agentledger.interfaces import ActionStatus, ActionType, Framework, ChainVerificationError


def make_chain(identity, tmp_path):
    return ReceiptChainImpl(identity, storage_path=str(tmp_path))


# ── Basic append / finalize ───────────────────────────────────────────────────

def test_append_returns_receipt_id(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    rid = chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool")
    assert isinstance(rid, str) and len(rid) == 36


def test_finalize_completed(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool", payload={"x": 1})
    chain.finalize_last(status=ActionStatus.COMPLETED, result={"ok": True})
    r = chain.iter_receipts()[0]
    assert r.action.status == ActionStatus.COMPLETED
    assert r.action.result_hash is not None


def test_finalize_failed(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.LLM_INVOKE, Framework.CUSTOM)
    chain.finalize_last(status=ActionStatus.FAILED, error="timeout")
    r = chain.iter_receipts()[0]
    assert r.action.status == ActionStatus.FAILED
    assert r.action.error == "timeout"


def test_finalize_noop_when_no_pending(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    chain.finalize_last(status=ActionStatus.COMPLETED)  # should not raise
    assert chain.iter_receipts() == []


def test_orphaned_receipt_force_failed(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool")
    chain.append(ActionType.LLM_INVOKE, Framework.CUSTOM)  # orphans first
    chain.finalize_last(status=ActionStatus.COMPLETED)
    receipts = chain.iter_receipts()
    assert receipts[0].action.status == ActionStatus.FAILED
    assert "orphaned" in receipts[0].action.error


# ── Chain integrity ───────────────────────────────────────────────────────────

def test_first_receipt_has_null_prev_hash(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    assert chain.iter_receipts()[0].prev_hash is None


def test_second_receipt_prev_hash_links_to_first(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    r1 = chain.iter_receipts()[0]
    chain.append(ActionType.LLM_INVOKE, Framework.CUSTOM)
    chain.finalize_last(status=ActionStatus.COMPLETED)
    r2 = chain.iter_receipts()[1]
    expected = sha256_hex(canonicalise_for_signing(r1))
    assert r2.prev_hash == expected


def test_receipts_have_signatures(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    assert chain.iter_receipts()[0].signature is not None


def test_verify_valid_chain(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    for _ in range(3):
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool", payload={"n": _})
        chain.finalize_last(status=ActionStatus.COMPLETED, result={"n": _})
    assert chain.verify() is True


def test_verify_empty_chain_raises(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    with pytest.raises(ValueError, match="empty"):
        chain.verify()


def test_iter_receipts_returns_copies(identity, tmp_path):
    """iter_receipts() returns deep copies — mutations don't affect internal state."""
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    copy = chain.iter_receipts()[0]
    copy.signature = "ff" * 64
    # Internal chain is unaffected — verify() must still pass
    assert chain.verify() is True


def test_verify_from_disk_detects_tampered_signature(identity, tmp_path):
    """verify_from_disk() catches tampered signature in JSONL file."""
    import json as _json
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    jsonl = list(Path(tmp_path).glob("*.jsonl"))[0]
    lines = jsonl.read_text().strip().splitlines()
    rec = _json.loads(lines[0])
    rec["signature"] = "ff" * 64
    jsonl.write_text(_json.dumps(rec) + "\n")
    ok, msg = chain.verify_from_disk()
    assert ok is False
    assert "signature" in msg


def test_verify_from_disk_detects_tampered_prev_hash(identity, tmp_path):
    """verify_from_disk() catches tampered prev_hash in JSONL file."""
    import json as _json
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    chain.append(ActionType.LLM_INVOKE, Framework.CUSTOM)
    chain.finalize_last(status=ActionStatus.COMPLETED)
    jsonl = list(Path(tmp_path).glob("*.jsonl"))[0]
    lines = jsonl.read_text().strip().splitlines()
    rec = _json.loads(lines[1])
    rec["prev_hash"] = "00" * 32
    lines[1] = _json.dumps(rec)
    jsonl.write_text("\n".join(lines) + "\n")
    ok, msg = chain.verify_from_disk()
    assert ok is False
    assert "prev_hash" in msg


# ── JSONL persistence ─────────────────────────────────────────────────────────

def test_jsonl_written_on_finalize(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    files = list(Path(tmp_path).glob("*.jsonl"))
    assert len(files) == 1
    lines = files[0].read_text().strip().split("\n")
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["action"]["status"] == "completed"


def test_jsonl_not_written_for_pending(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool")
    files = list(Path(tmp_path).glob("*.jsonl"))
    assert len(files) == 0 or all(
        f.read_text().strip() == "" for f in files
    )


def test_jsonl_prev_hash_matches_core(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    chain.append(ActionType.LLM_INVOKE, Framework.CUSTOM)
    chain.finalize_last(status=ActionStatus.COMPLETED)

    lines = list(Path(tmp_path).glob("*.jsonl"))[0].read_text().strip().split("\n")
    r1 = json.loads(lines[0])
    r2 = json.loads(lines[1])
    # CLI computes prev_hash WITHOUT signature
    r1_no_sig = {k: v for k, v in r1.items() if k != "signature"}
    expected = sha256_hex(
        json.dumps(r1_no_sig, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()
    )
    assert r2["prev_hash"] == expected


# ── Thread safety ─────────────────────────────────────────────────────────────

def test_concurrent_appends_all_finalized(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    errors = []

    def worker(n):
        try:
            chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool", payload={"n": n})
            chain.finalize_last(status=ActionStatus.COMPLETED, result={"n": n})
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Thread errors: {errors}"
    assert chain.verify() is True
    assert len(chain.iter_receipts()) == 10


def test_get_receipt_by_id(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    rid = chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="test_tool")
    chain.finalize_last(status=ActionStatus.COMPLETED)
    r = chain.get_receipt(rid)
    assert r.receipt_id == rid


def test_get_receipt_missing_raises(identity, tmp_path):
    chain = make_chain(identity, tmp_path)
    with pytest.raises(KeyError):
        chain.get_receipt("nonexistent")
