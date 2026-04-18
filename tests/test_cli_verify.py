"""
Tests for CLI verify module — agentledger/cli/verify.py

Tests the standalone verification logic without depending on the core implementation.
Verifies: canonical JSON, hash chain, Ed25519 signature verification, checkpoints.

No network, no external dependencies beyond the stdlib.
"""

import json
import tempfile
import pytest
from pathlib import Path

from agentledger.cli.verify import (
    canonicalise,
    compute_sha256_hex,
    iter_jsonl,
    verify_receipt_chain,
    main,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_receipt_dict(
    receipt_id,
    prev_hash,
    action_type="tool_call",
    status="completed",
    payload_hash=None,
    result_hash=None,
    error=None,
    signature=None,
):
    """Build a minimal receipt dict matching the schema."""
    d = {
        "action": {
            "error": error,
            "framework": "langchain",
            "payload_hash": payload_hash or compute_sha256_hex(b"payload"),
            "result_hash": result_hash,
            "status": status,
            "tool_name": "test-tool",
            "type": action_type,
        },
        "agent_id": "abcd" * 16,
        "chain_id": "abcd" * 16,
        "cross_agent_ref": None,
        "prev_hash": prev_hash,
        "principal_id": "test-principal",
        "receipt_id": receipt_id,
        "schema_version": "0.1",
        "timestamp": "2026-04-19T00:00:00+00:00",
    }
    if signature is not None:
        d["signature"] = signature
    return d


def write_jsonl(path, receipts):
    with open(path, "w", encoding="utf-8") as f:
        for r in receipts:
            f.write(json.dumps(r, separators=(",", ":"), sort_keys=True, ensure_ascii=False) + "\n")


# ─── Unit tests ───────────────────────────────────────────────────────────────

class TestCanonicalise:
    """canonicalise() produces deterministic, sorted, UTF-8 JSON bytes."""

    def test_deterministic(self):
        d = {"b": 2, "a": 1}
        assert canonicalise(d) == canonicalise(d)

    def test_keys_sorted(self):
        d = {"z": 1, "a": 2}
        canon = canonicalise(d).decode()
        keys = [k for k in json.loads(canon).keys()]
        assert keys == sorted(keys)

    def test_no_extra_whitespace(self):
        d = {"a": 1}
        assert canonicalise(d) == b'{"a":1}'

    def test_nested_keys_sorted(self):
        d = {"outer": {"z": 1, "a": 2}}
        canon = json.loads(canonicalise(d))
        outer_keys = list(canon["outer"].keys())
        assert outer_keys == sorted(outer_keys)


class TestComputeSha256Hex:
    def test_empty_bytes(self):
        assert compute_sha256_hex(b"") == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_known_value(self):
        assert compute_sha256_hex(b"hello") == (
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )


class TestIterJsonl:
    def test_parses_valid_jsonl(self, tmp_path):
        path = tmp_path / "test.jsonl"
        with open(path, "w") as f:
            f.write('{"a":1}\n{"b":2}\n')
        results = list(iter_jsonl(path))
        assert len(results) == 2
        assert results[0]["a"] == 1

    def test_skips_empty_lines(self, tmp_path):
        path = tmp_path / "test.jsonl"
        with open(path, "w") as f:
            f.write('{"a":1}\n\n{"b":2}\n')
        assert len(list(iter_jsonl(path))) == 2

    def test_invalid_json_raises(self, tmp_path):
        path = tmp_path / "bad.jsonl"
        with open(path, "w") as f:
            f.write('{"a":1}\nnot-json\n')
        with pytest.raises(ValueError, match="invalid JSON"):
            list(iter_jsonl(path))


# ─── Integration tests — full chain verification ───────────────────────────────

class TestVerifyChain:
    """Integration: verify_receipt_chain() validates prev_hash linkage + signatures."""

    def test_empty_chain_returns_ok(self, tmp_path):
        path = tmp_path / "empty.jsonl"
        path.write_text("", encoding="utf-8")
        ok, msg = verify_receipt_chain(path)
        assert ok is True

    def test_single_genesis_receipt_valid(self, tmp_path, identity):
        """First receipt (prev_hash=null) with valid sig passes."""
        path = tmp_path / "single.jsonl"

        # Build genesis receipt
        r = make_receipt_dict("receipt-1", prev_hash=None, signature=None)
        write_jsonl(path, [r])

        # Verify without pubkey (skip sig check)
        ok, msg = verify_receipt_chain(path)
        assert ok is True

    def test_prev_hash_mismatch_fails(self, tmp_path):
        """Receipt whose prev_hash doesn't match expected chain fails."""
        path = tmp_path / "broken.jsonl"

        # Genesis + second receipt with WRONG prev_hash
        genesis = make_receipt_dict("receipt-1", prev_hash=None, signature="sig1")
        bad_second = make_receipt_dict("receipt-2", prev_hash="wrong-hash", signature="sig2")
        write_jsonl(path, [genesis, bad_second])

        ok, msg = verify_receipt_chain(path)
        assert ok is False
        assert "prev_hash mismatch" in msg

    def test_full_chain_valid_with_signature(self, tmp_path, identity):
        """Full chain with correct prev_hash and Ed25519 sig passes."""
        path = tmp_path / "valid.jsonl"

        # Generate two signed receipts manually
        from agentledger.core.receipt import canonicalise_for_signing, receipt_to_dict, sha256_hex
        from agentledger.interfaces import ActionData, ActionStatus, ActionType, Framework, Receipt

        # Receipt 1 (genesis)
        r1 = Receipt(
            receipt_id="r1",
            chain_id=identity.agent_id,
            timestamp="2026-04-19T00:00:00+00:00",
            agent_id=identity.agent_id,
            principal_id=identity.principal_id,
            action=ActionData(
                type=ActionType.TOOL_CALL,
                framework=Framework.LANGCHAIN,
                status=ActionStatus.COMPLETED,
            ),
            prev_hash=None,
        )
        sig1 = identity.sign(canonicalise_for_signing(r1))
        r1_dict = receipt_to_dict(r1)
        r1_dict["signature"] = sig1.hex()

        # Receipt 2 (chained)
        prev1 = sha256_hex(canonicalise_for_signing(r1))
        r2 = Receipt(
            receipt_id="r2",
            chain_id=identity.agent_id,
            timestamp="2026-04-19T00:00:01+00:00",
            agent_id=identity.agent_id,
            principal_id=identity.principal_id,
            action=ActionData(
                type=ActionType.LLM_INVOKE,
                framework=Framework.LANGCHAIN,
                status=ActionStatus.COMPLETED,
            ),
            prev_hash=prev1,
        )
        sig2 = identity.sign(canonicalise_for_signing(r2))
        r2_dict = receipt_to_dict(r2)
        r2_dict["signature"] = sig2.hex()

        write_jsonl(path, [r1_dict, r2_dict])

        # Verify with pubkey
        pubkey_bytes = bytes.fromhex(identity.agent_id)
        ok, msg = verify_receipt_chain(path, agent_public_key=pubkey_bytes)
        assert ok is True, msg

    def test_tampered_signature_fails(self, tmp_path, identity):
        """Chain passes prev_hash but fails signature check."""
        path = tmp_path / "tampered.jsonl"

        from agentledger.core.receipt import canonicalise_for_signing, receipt_to_dict
        from agentledger.interfaces import ActionData, ActionStatus, ActionType, Framework, Receipt

        r1 = Receipt(
            receipt_id="r1",
            chain_id=identity.agent_id,
            timestamp="2026-04-19T00:00:00+00:00",
            agent_id=identity.agent_id,
            principal_id=identity.principal_id,
            action=ActionData(
                type=ActionType.TOOL_CALL,
                framework=Framework.LANGCHAIN,
                status=ActionStatus.COMPLETED,
            ),
            prev_hash=None,
        )
        sig1 = identity.sign(canonicalise_for_signing(r1))
        r1_dict = receipt_to_dict(r1)
        r1_dict["signature"] = sig1.hex()
        # Tamper: flip a byte in signature
        tampered_sig = bytearray(sig1)
        tampered_sig[0] ^= 0xFF
        r1_dict["signature"] = bytes(tampered_sig).hex()

        write_jsonl(path, [r1_dict])

        pubkey_bytes = bytes.fromhex(identity.agent_id)
        ok, msg = verify_receipt_chain(path, agent_public_key=pubkey_bytes)
        assert ok is False
        assert "signature" in msg.lower()


class TestVerifyCheckpoint:
    """Checkpoint verification logic."""

    def test_checkpoint_cumulative_hash_valid(self, tmp_path, identity):
        """Valid checkpoint with matching cumulative hash passes."""
        path = tmp_path / "with_checkpoint.jsonl"

        from agentledger.core.receipt import canonicalise_for_signing, receipt_to_dict, sha256_hex
        from agentledger.interfaces import ActionData, ActionStatus, ActionType, Framework, Receipt

        # Build two receipts
        r1 = Receipt(
            receipt_id="r1",
            chain_id=identity.agent_id,
            timestamp="2026-04-19T00:00:00+00:00",
            agent_id=identity.agent_id,
            principal_id=identity.principal_id,
            action=ActionData(type=ActionType.TOOL_CALL, framework=Framework.LANGCHAIN, status=ActionStatus.COMPLETED),
            prev_hash=None,
        )
        sig1 = identity.sign(canonicalise_for_signing(r1))
        r1_dict = receipt_to_dict(r1)
        r1_dict["signature"] = sig1.hex()

        r2 = Receipt(
            receipt_id="r2",
            chain_id=identity.agent_id,
            timestamp="2026-04-19T00:00:01+00:00",
            agent_id=identity.agent_id,
            principal_id=identity.principal_id,
            action=ActionData(type=ActionType.LLM_INVOKE, framework=Framework.LANGCHAIN, status=ActionStatus.COMPLETED),
            prev_hash=sha256_hex(canonicalise_for_signing(r1)),
        )
        sig2 = identity.sign(canonicalise_for_signing(r2))
        r2_dict = receipt_to_dict(r2)
        r2_dict["signature"] = sig2.hex()

        # Checkpoint after r1 (count=1)
        batch_cumulative = sha256_hex(canonicalise_for_signing(r1))
        ckpt = {
            "at_receipt_id": "r1",
            "checkpoint": True,
            "cumulative_hash": batch_cumulative,
            "receipt_count": 1,
        }
        sig_ckpt = identity.sign(json.dumps(ckpt, separators=(",", ":"), sort_keys=True).encode())
        ckpt["signature"] = sig_ckpt.hex()

        write_jsonl(path, [r1_dict, ckpt, r2_dict])

        ok, msg = verify_receipt_chain(path, checkpoint_only=True)
        assert ok is True, msg


class TestMainExitCodes:
    """main() returns correct exit codes."""

    def test_missing_file_returns_2(self):
        result = main(["nonexistent.jsonl"])
        assert result == 2

    def test_empty_dir_returns_0(self, tmp_path):
        result = main([str(tmp_path)])
        assert result == 0


# ─── Fixture ─────────────────────────────────────────────────────────────────

@pytest.fixture
def identity():
    """A real AgentIdentityImpl for generating valid signatures."""
    from tests.conftest import NoopBinding
    from agentledger.core.identity import AgentIdentityImpl
    return AgentIdentityImpl.create(binding=NoopBinding())
