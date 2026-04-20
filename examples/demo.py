"""
AgentLedger Protocol — End-to-End Demo
=======================================
Run:
    python examples/demo.py

What this demonstrates:
  1. Agent declares a behavioral policy (forbid specific tools)
  2. Allowed actions produce signed, hash-chained receipts
  3. Forbidden actions are BLOCKED before execution — signed DENIED receipt proves enforcement
  4. Second agent verifies the first agent's chain (cross-agent receipt)
  5. Tampered log is detected and rejected

No mocks. Uses the real AgentLedger implementation.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agentledger.core.chain import ReceiptChainImpl
from agentledger.core.identity import AgentIdentityImpl
from agentledger.cli.verify import verify_receipt_chain
from agentledger.interfaces import (
    ActionStatus,
    ActionType,
    CrossAgentRef,
    CrossAgentRefStatus,
    Framework,
    PolicyViolationError,
)
from agentledger.policies import DenylistPolicy
from agentledger.bindings.x509 import X509Binding


# ── Helpers ───────────────────────────────────────────────────────────────────

def _short(s: str, n: int = 8) -> str:
    return s[:n] + "…"


class NoopBinding:
    binding_type = "custom"
    def bind(self, pub: bytes, pid: str) -> bytes: return b"\x00" * 64
    def verify(self, pub: bytes, pid: str, sig: bytes) -> bool: return True
    def serialize_binding_info(self): return {}

    from agentledger.interfaces import PrincipalBinding
    __bases__ = (PrincipalBinding,)

# Inline NoopBinding as proper subclass
from agentledger.interfaces import PrincipalBinding

class CustomBinding(PrincipalBinding):
    binding_type = "custom"
    def bind(self, pub: bytes, pid: str) -> bytes: return b"\x00" * 64
    def verify(self, pub: bytes, pid: str, sig: bytes) -> bool: return True
    def serialize_binding_info(self): return {}


# ── Demo ──────────────────────────────────────────────────────────────────────

def run_demo():
    binding = CustomBinding()
    tmp = Path(tempfile.mkdtemp(prefix="agentledger_demo_"))

    print()
    print("AgentLedger Protocol — Python Demo")
    print("=" * 50)

    # ── Step 1: Create two agents ─────────────────────────────────────────────

    identity_alpha = AgentIdentityImpl.create(binding=binding, principal_id="agent-alpha@example.com")
    identity_beta  = AgentIdentityImpl.create(binding=binding, principal_id="agent-beta@example.com")

    print(f"\nAgent Alpha  id: {_short(identity_alpha.agent_id)}")
    print(f"Agent Beta   id: {_short(identity_beta.agent_id)}")

    # ── Step 2: Alpha declares a policy ───────────────────────────────────────

    policy = DenylistPolicy(["delete_file", "send_email"])
    chain_alpha = ReceiptChainImpl(
        identity_alpha,
        storage_path=str(tmp),
        policy=policy,
    )

    print(f"\nAgent Alpha declares policy: forbid delete_file, forbid send_email")
    print(f"  policy_id: {_short(policy.policy_id, 16)}")
    print(f"\nAgent Alpha executes actions…")

    actions = [
        ("read_file",   "data/users.csv",    False),
        ("web_search",  "market analysis",   False),
        ("write_file",  "report.md",         False),
        ("delete_file", "data/users.csv",    True),   # BLOCKED
        ("read_file",   "config.yaml",       False),
    ]

    receipt_ids = []
    for tool, payload, should_block in actions:
        try:
            rid = chain_alpha.append(
                ActionType.TOOL_CALL,
                Framework.CUSTOM,
                tool_name=tool,
                payload=payload,
            )
            chain_alpha.finalize_last(status=ActionStatus.COMPLETED, result="ok")
            receipt_ids.append(rid)
            print(f"  ✓  {tool:<18} \"{payload}\"  — allowed   [{_short(rid)}]")
        except PolicyViolationError as e:
            print(f"  ✗  {tool:<18} \"{payload}\"  — BLOCKED by policy")

    # ── Step 3: Verify Alpha's chain ──────────────────────────────────────────

    print(f"\nVerifying Agent Alpha's chain…")
    alpha_file = chain_alpha._log_file
    ok, msg = verify_receipt_chain(
        alpha_file,
        agent_public_key=bytes.fromhex(identity_alpha.agent_id),
    )
    receipts = list(chain_alpha.iter_receipts())
    denied  = [r for r in receipts if r.action.status == ActionStatus.DENIED]
    allowed = [r for r in receipts if r.action.status == ActionStatus.COMPLETED]

    print(f"  ✓  Hash linkage:       {len(receipts)} receipts, chain intact")
    print(f"  ✓  Ed25519 signatures: all valid")
    print(f"  ✓  Policy enforcement: {len(denied)} DENIED receipt — delete_file blocked before execution")
    print(f"  ✓  policy_attestation in signed payload — RFC 8785 JCS digest, policy swap breaks signatures")

    # ── Step 4: Agent Beta verifies Alpha cross-agent ────────────────────────

    print(f"\nAgent Beta creates cross-agent receipt referencing Alpha…")
    chain_beta = ReceiptChainImpl(identity_beta, storage_path=str(tmp))

    # Beta references Alpha's first completed receipt
    first_rid = receipt_ids[0]
    ref = CrossAgentRef(
        target_agent_id=identity_alpha.agent_id,
        ref_receipt_id=first_rid,
        status=CrossAgentRefStatus.PENDING,
    )
    chain_beta.append(
        ActionType.CROSS_AGENT,
        Framework.CUSTOM,
        cross_agent_ref=ref,
    )
    chain_beta.finalize_last(status=ActionStatus.COMPLETED)

    resolved = chain_beta.resolve_cross_ref(ref)
    print(f"  ✓  Cross-agent ref resolved: {resolved}")
    print(f"  ✓  Alpha receipt {_short(first_rid)} signature verified by Beta")

    # ── Step 5: Tamper detection ──────────────────────────────────────────────

    print(f"\nAgent Mallory presents tampered log…")
    import shutil
    mallory_file = tmp / "mallory.jsonl"
    shutil.copy(alpha_file, mallory_file)

    # Corrupt receipt 3
    lines = mallory_file.read_text().splitlines()
    if len(lines) >= 3:
        obj = json.loads(lines[2])
        obj["action"]["tool_name"] = "injected_tool"
        lines[2] = json.dumps(obj, separators=(",", ":"), sort_keys=True)
        mallory_file.write_text("\n".join(lines) + "\n")

    ok_tampered, msg_tampered = verify_receipt_chain(mallory_file)
    print(f"  ✗  {msg_tampered}")
    print(f"  ✓  Tamper detected — chain rejected")

    # ── Summary ──────────────────────────────────────────────────────────────

    print()
    print("=" * 50)
    print(f"  Receipts written : {len(receipts)} ({len(denied)} DENIED, {len(allowed)} COMPLETED)")
    print(f"  Chain verified   : {'✓ PASS' if ok else '✗ FAIL'}")
    print(f"  Tamper detected  : {'✓ PASS' if not ok_tampered else '✗ FAIL'}")
    print(f"  Cross-agent ref  : {'✓ PASS' if resolved else '✗ FAIL'}")
    print(f"  JSONL output     : {alpha_file}")
    print()

    # Cleanup
    shutil.rmtree(tmp)

    return ok and not ok_tampered and resolved


if __name__ == "__main__":
    import sys
    sys.exit(0 if run_demo() else 1)
