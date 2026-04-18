"""Tests for receipt serialisation and canonical hashing."""

import json
import pytest
from agentledger.core.receipt import (
    canonicalise_for_signing,
    receipt_to_dict,
    sha256_hex,
)
from agentledger.interfaces import (
    ActionData, ActionStatus, ActionType, Framework, Receipt
)


def make_receipt(**kwargs):
    defaults = dict(
        receipt_id="test-uuid",
        chain_id="abcd" * 16,
        timestamp="2026-04-19T00:00:00+00:00",
        agent_id="abcd" * 16,
        principal_id="test-principal",
        action=ActionData(
            type=ActionType.TOOL_CALL,
            framework=Framework.CUSTOM,
            status=ActionStatus.COMPLETED,
        ),
    )
    defaults.update(kwargs)
    return Receipt(**defaults)


def test_sha256_hex_known_value():
    result = sha256_hex(b"")
    assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_canonicalise_is_deterministic():
    r = make_receipt()
    b1 = canonicalise_for_signing(r)
    b2 = canonicalise_for_signing(r)
    assert b1 == b2


def test_canonicalise_excludes_signature():
    r = make_receipt()
    r.signature = "deadsig"
    payload = canonicalise_for_signing(r)
    parsed = json.loads(payload)
    assert "signature" not in parsed


def test_canonicalise_keys_sorted():
    r = make_receipt()
    payload = canonicalise_for_signing(r)
    parsed_raw = payload.decode()
    # top-level keys should appear in lexicographic order
    keys = [k for k in json.loads(payload).keys()]
    assert keys == sorted(keys)


def test_canonicalise_action_keys_sorted():
    r = make_receipt()
    payload = canonicalise_for_signing(r)
    action = json.loads(payload)["action"]
    keys = list(action.keys())
    assert keys == sorted(keys)


def test_receipt_to_dict_includes_signature():
    r = make_receipt()
    r.signature = "abc123"
    d = receipt_to_dict(r, include_signature=True)
    assert d["signature"] == "abc123"


def test_receipt_to_dict_excludes_signature():
    r = make_receipt()
    r.signature = "abc123"
    d = receipt_to_dict(r, include_signature=False)
    assert "signature" not in d


def test_different_receipts_produce_different_hashes():
    r1 = make_receipt(receipt_id="uuid-1")
    r2 = make_receipt(receipt_id="uuid-2")
    assert canonicalise_for_signing(r1) != canonicalise_for_signing(r2)


def test_prev_hash_null_for_first_receipt():
    r = make_receipt()
    d = receipt_to_dict(r)
    assert d["prev_hash"] is None


def test_non_ascii_payload_hash_consistent():
    r = make_receipt()
    r.action.payload_hash = sha256_hex("日本語テスト".encode("utf-8"))
    b1 = canonicalise_for_signing(r)
    b2 = canonicalise_for_signing(r)
    assert b1 == b2
    assert json.loads(b1)["action"]["payload_hash"] == r.action.payload_hash
