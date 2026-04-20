"""
Tests for CLI arg forwarding, verify checkpoint path, and inspect command.
Covers agentledger/cli.py (0%), agentledger/cli/verify.py (72% gaps),
and agentledger/cli/inspect.py (0%).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from agentledger.cli import verify as verify_mod
from agentledger.cli import inspect as inspect_mod
from agentledger import cli as cli_mod
from agentledger.core.chain import ReceiptChainImpl
from agentledger.core.identity import AgentIdentityImpl
from agentledger.interfaces import ActionStatus, ActionType, Framework


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def chain_with_receipts(noop_binding, tmp_path):
    identity = AgentIdentityImpl.create(binding=noop_binding)
    chain = ReceiptChainImpl(identity, storage_path=str(tmp_path))
    for i in range(3):
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name=f"tool_{i}")
        chain.finalize_last(status=ActionStatus.COMPLETED)
    return chain, identity


# ── agentledger/cli.py arg forwarding ─────────────────────────────────────────

class TestCliArgForwarding:

    def test_verify_no_flags(self, chain_with_receipts, tmp_path, capsys):
        chain, identity = chain_with_receipts
        rc = cli_mod.main(["verify", str(chain._log_file)])
        assert rc == 0

    def test_verify_with_agent_public_key(self, chain_with_receipts, capsys):
        chain, identity = chain_with_receipts
        rc = cli_mod.main([
            "verify", str(chain._log_file),
            "--agent-public-key", identity.agent_id,
        ])
        assert rc == 0

    def test_verify_with_checkpoint_only(self, chain_with_receipts, capsys):
        chain, identity = chain_with_receipts
        rc = cli_mod.main(["verify", str(chain._log_file), "--checkpoint-only"])
        assert rc == 0

    def test_verify_bad_file_returns_nonzero(self, tmp_path):
        rc = cli_mod.main(["verify", str(tmp_path / "nonexistent.jsonl")])
        assert rc == 2

    def test_inspect_no_flags(self, chain_with_receipts, capsys):
        chain, _ = chain_with_receipts
        rc = cli_mod.main(["inspect", str(chain._log_file)])
        assert rc == 0

    def test_inspect_verbose(self, chain_with_receipts, capsys):
        chain, _ = chain_with_receipts
        rc = cli_mod.main(["inspect", str(chain._log_file), "--verbose"])
        assert rc == 0

    def test_verify_no_empty_strings_passed(self, chain_with_receipts, monkeypatch):
        """Ensure empty strings are not forwarded to verify.main()."""
        chain, _ = chain_with_receipts
        captured_argv = []

        def fake_verify_main(argv):
            captured_argv.extend(argv)
            return 0

        monkeypatch.setattr(verify_mod, "main", fake_verify_main)
        cli_mod.main(["verify", str(chain._log_file)])
        assert "" not in captured_argv

    def test_inspect_no_empty_strings_passed(self, chain_with_receipts, monkeypatch):
        chain, _ = chain_with_receipts
        captured_argv = []

        def fake_inspect_main(argv):
            captured_argv.extend(argv)
            return 0

        monkeypatch.setattr(inspect_mod, "main", fake_inspect_main)
        cli_mod.main(["inspect", str(chain._log_file)])
        assert "" not in captured_argv


# ── cli/verify.py checkpoint_only path ───────────────────────────────────────

class TestVerifyCheckpointOnly:

    def _make_chain_with_checkpoint(self, noop_binding, tmp_path, n=100):
        """Create a chain long enough to trigger a checkpoint (interval=100)."""
        identity = AgentIdentityImpl.create(binding=noop_binding)
        chain = ReceiptChainImpl(
            identity, storage_path=str(tmp_path), checkpoint_interval=10
        )
        for i in range(n):
            chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name=f"t{i}")
            chain.finalize_last(status=ActionStatus.COMPLETED)
        return chain, identity

    def test_checkpoint_only_valid_chain(self, noop_binding, tmp_path):
        chain, identity = self._make_chain_with_checkpoint(noop_binding, tmp_path)
        ok, msg = verify_mod.verify_receipt_chain(
            chain._log_file,
            checkpoint_only=True,
            agent_public_key=bytes.fromhex(identity.agent_id),
        )
        assert ok, msg

    def test_checkpoint_only_detects_tail_tamper(self, noop_binding, tmp_path):
        chain, identity = self._make_chain_with_checkpoint(noop_binding, tmp_path)

        # Tamper the last line in the file
        lines = chain._log_file.read_text().splitlines()
        last = json.loads(lines[-1])
        if not last.get("checkpoint"):
            last["action"]["tool_name"] = "tampered"
            lines[-1] = json.dumps(last, separators=(",", ":"), sort_keys=True)
            chain._log_file.write_text("\n".join(lines) + "\n")
            ok, msg = verify_mod.verify_receipt_chain(
                chain._log_file,
                checkpoint_only=True,
            )
            assert not ok

    def test_full_verify_with_key(self, noop_binding, tmp_path):
        identity = AgentIdentityImpl.create(binding=noop_binding)
        chain = ReceiptChainImpl(identity, storage_path=str(tmp_path))
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="t")
        chain.finalize_last(status=ActionStatus.COMPLETED)
        ok, msg = verify_mod.verify_receipt_chain(
            chain._log_file,
            agent_public_key=bytes.fromhex(identity.agent_id),
        )
        assert ok, msg

    def test_verify_invalid_public_key_hex(self, noop_binding, tmp_path):
        identity = AgentIdentityImpl.create(binding=noop_binding)
        chain = ReceiptChainImpl(identity, storage_path=str(tmp_path))
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="t")
        chain.finalize_last(status=ActionStatus.COMPLETED)
        rc = verify_mod.main([str(chain._log_file), "--agent-public-key", "zz" * 32])
        assert rc == 2

    def test_verify_directory(self, noop_binding, tmp_path):
        identity = AgentIdentityImpl.create(binding=noop_binding)
        chain = ReceiptChainImpl(identity, storage_path=str(tmp_path))
        chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="t")
        chain.finalize_last(status=ActionStatus.COMPLETED)
        rc = verify_mod.main([str(tmp_path)])
        assert rc == 0

    def test_verify_empty_directory(self, tmp_path, capsys):
        rc = verify_mod.main([str(tmp_path)])
        assert rc == 0


# ── cli/inspect.py ─────────────────────────────────────────────────────────────

class TestInspect:

    def test_inspect_file(self, chain_with_receipts, capsys):
        chain, _ = chain_with_receipts
        rc = inspect_mod.main([str(chain._log_file)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "tool_" in out

    def test_inspect_verbose(self, chain_with_receipts, capsys):
        chain, _ = chain_with_receipts
        rc = inspect_mod.main([str(chain._log_file), "--verbose"])
        assert rc == 0

    def test_inspect_directory(self, chain_with_receipts, capsys):
        chain, _ = chain_with_receipts
        rc = inspect_mod.main([str(chain._log_file.parent)])
        assert rc == 0

    def test_inspect_missing_file(self, tmp_path, capsys):
        rc = inspect_mod.main([str(tmp_path / "missing.jsonl")])
        assert rc == 2
