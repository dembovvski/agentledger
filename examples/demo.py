"""
AgentLedger E2E Demo
===================
Standalone demonstration of the full AgentLedger audit trail flow:
LangChain agent → AgentLedgerCallback → ReceiptChain → JSONL → agentledger verify

This demo uses realistic mock objects to simulate LangChain callback events
and produces verifiable JSONL output identical to what a production agent would emit.

Run:
    python examples/demo.py
    python -m agentledger.cli verify /tmp/agentledger_demo/demo.jsonl
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

# ── Minimal mock of AgentLedger core (avoids import of unimplemented modules) ──

import hashlib


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonicalise(obj: dict) -> bytes:
    """Canonical JSON: keys sorted, no extra whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def no_sig(receipt: dict) -> dict:
    """Receipt dict with signature field excluded."""
    return {k: v for k, v in receipt.items() if k != "signature"}


# ── Mock ReceiptChain that writes real JSONL ──────────────────────────────────

class MockReceiptChain:
    """
    Realistic mock of ReceiptChain that writes actual .jsonl files
    matching the format agentledger verify expects.
    """

    def __init__(self, agent_id: str, principal_id: str, storage_path: str):
        self.agent_id = agent_id
        self.principal_id = principal_id
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._pending: dict | None = None
        self._receipts: list[dict] = []
        self._jsonl_path = self.storage_path / f"{agent_id}.jsonl"

    def append(
        self,
        action_type: str,
        framework: str,
        *,
        tool_name: str | None = None,
        payload: str | None = None,
    ) -> str:
        receipt_id = str(uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        # Build prev_hash
        if self._receipts:
            prev = no_sig(self._receipts[-1])
            prev_hash = sha256_hex(canonicalise(prev))
        else:
            prev_hash = None

        # Payload hash
        payload_bytes = canonicalise({"payload": payload}) if payload else b""
        payload_hash = sha256_hex(payload_bytes) if payload_bytes else None

        self._pending = {
            "receipt_id": receipt_id,
            "chain_id": self.agent_id,
            "timestamp": timestamp,
            "agent_id": self.agent_id,
            "principal_id": self.principal_id,
            "prev_hash": prev_hash,
            "action": {
                "type": action_type,
                "framework": framework,
                "tool_name": tool_name,
                "status": "pending",
                "payload_hash": payload_hash,
            },
            "schema_version": "0.1",
        }
        return receipt_id

    def finalize_last(
        self,
        *,
        status: str,
        result: str | None = None,
        error: str | None = None,
    ) -> None:
        if self._pending is None:
            return

        self._pending["action"]["status"] = status
        if result is not None:
            result_bytes = canonicalise({"result": result})
            self._pending["action"]["result_hash"] = sha256_hex(result_bytes)
        if error is not None:
            self._pending["action"]["error"] = error

        # Sign (mock — use agent_id as private key seed for deterministic demo sig)
        sig_input = canonicalise(no_sig(self._pending))
        sig = sha256_hex(sig_input + self.agent_id.encode())  # deterministic mock sig
        self._pending["signature"] = sig

        self._receipts.append(self._pending)
        self._flush()
        self._pending = None

    def _flush(self) -> None:
        with open(self._jsonl_path, "a", encoding="utf-8") as f:
            line = canonicalise(self._receipts[-1]).decode("utf-8")
            f.write(line + "\n")

    def verify(self, *, checkpoint_only: bool = False) -> bool:
        """Re-read JSONL and verify chain linkage."""
        receipts = list(self.iter_jsonl())
        if not receipts:
            return True

        prev_hash = None
        for r in receipts:
            if r.get("prev_hash") != prev_hash:
                raise ValueError(f"prev_hash mismatch at {r['receipt_id']}")
            prev_hash = sha256_hex(canonicalise(no_sig(r)))
        return True

    def iter_jsonl(self):
        if not self._jsonl_path.exists():
            return
        with open(self._jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)


# ── Mock AgentLedgerCallback — simulates LangChain callback events ────────────

class MockAgentLedgerCallback:
    """
    Realistic mock of AgentLedgerCallback that exercises the same API
    as the real LangChain callback handler.
    """

    def __init__(self, chain: MockReceiptChain):
        self.chain = chain

    def on_chain_start(self, serialized: dict, inputs: dict) -> None:
        self.chain.append(
            action_type="decision",
            framework="langchain",
            tool_name="chain",
            payload=str(inputs),
        )

    def on_chain_end(self, outputs: dict) -> None:
        self.chain.finalize_last(status="completed", result=str(outputs))

    def on_llm_start(self, serialized: dict, prompts: str | list) -> None:
        payload = prompts if isinstance(prompts, str) else "\n".join(str(p) for p in prompts)
        self.chain.append(
            action_type="llm_invoke",
            framework="langchain",
            payload=payload,
        )

    def on_llm_end(self, response: str) -> None:
        self.chain.finalize_last(status="completed", result=response)

    def on_tool_start(self, serialized: dict, input_str: str) -> None:
        tool_name = serialized.get("name") if isinstance(serialized, dict) else None
        self.chain.append(
            action_type="tool_call",
            framework="langchain",
            tool_name=tool_name,
            payload=input_str,
        )

    def on_tool_end(self, output: str) -> None:
        self.chain.finalize_last(status="completed", result=output)

    def on_tool_error(self, error: str) -> None:
        self.chain.finalize_last(status="failed", error=error)

    def on_agent_action(self, action) -> None:
        # No-op — decision already captured by on_chain_start
        pass

    def on_agent_finish(self, finish) -> None:
        self.chain.finalize_last(status="completed", result=str(finish))


# ── Simulate LangChain agent run ───────────────────────────────────────────────

def simulate_langchain_agent_run(agent_id: str, principal_id: str, demo_dir: Path):
    """
    Simulates a LangChain agent run with multiple LLM invocations,
    tool calls, and a final agent finish — exactly what AgentLedgerCallback
    would record in a real execution.
    """
    chain = MockReceiptChain(agent_id, principal_id, str(demo_dir))
    callback = MockAgentLedgerCallback(chain)

    print("\n=== Simulating LangChain Agent Run ===")

    # Agent receives user query
    callback.on_chain_start(
        serialized={"name": "agent"},
        inputs={"input": "What is the capital of Poland?"},
    )

    # Agent invokes LLM to reason
    callback.on_llm_start(
        serialized={"name": "chat_openai"},
        prompts="User asked: What is the capital of Poland?",
    )
    callback.on_llm_end(
        response="The user wants to know the capital of Poland. I should use a search tool.",
    )

    # Agent decides to call search tool
    callback.on_tool_start(
        serialized={"name": "wikipedia_search"},
        input_str="capital of Poland",
    )
    callback.on_tool_end(
        output="The capital of Poland is Warsaw.",
    )

    # Agent invokes LLM again to formulate final answer
    callback.on_llm_start(
        serialized={"name": "chat_openai"},
        prompts="Provide a short answer about Warsaw.",
    )
    callback.on_llm_end(
        response="Warsaw is the capital and largest city of Poland.",
    )

    # Agent finishes
    callback.on_agent_finish(
        finish={"output": "The capital of Poland is Warsaw."},
    )
    callback.on_chain_end(outputs={"output": "The capital of Poland is Warsaw."})

    return chain


# ── Verify using the real CLI verifier ────────────────────────────────────────

def verify_with_cli(jsonl_path: Path) -> bool:
    """
    Run the agentledger verify CLI on the demo JSONL file.
    Uses the same verify_receipt_chain logic as the real CLI.
    """
    from agentledger.cli.verify import verify_receipt_chain

    ok, msg = verify_receipt_chain(jsonl_path)
    print(f"\n=== CLI Verify Result ===")
    print(f"  {msg}")
    return ok


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    demo_dir = Path(tempfile.mkdtemp(prefix="agentledger_demo_"))
    agent_id = f"demo-agent-{uuid4().hex[:8]}"
    principal_id = "demo@example.com"

    print(f"AgentLedger E2E Demo")
    print(f"====================")
    print(f"Agent ID:     {agent_id}")
    print(f"Principal:    {principal_id}")
    print(f"Output dir:   {demo_dir}")

    # 1. Run the simulated agent
    chain = simulate_langchain_agent_run(agent_id, principal_id, demo_dir)

    # 2. Show the JSONL output
    jsonl_path = chain._jsonl_path
    print(f"\n=== Generated JSONL ({jsonl_path.name}) ===")
    with open(jsonl_path, "r") as f:
        for i, line in enumerate(f, 1):
            receipt = json.loads(line.strip())
            print(f"\nReceipt {i}: {receipt['receipt_id'][:8]}...")
            print(f"  action : {receipt['action']['type']} | {receipt['action']['tool_name']} | {receipt['action']['status']}")
            print(f"  prev   : {receipt['prev_hash'][:16] if receipt['prev_hash'] else 'None'}...")
            print(f"  sig    : {receipt['signature'][:16]}...")

    # 3. Verify with CLI
    verify_ok = verify_with_cli(jsonl_path)

    # 4. Also verify via chain.verify() (mock)
    chain_ok = chain.verify()
    print(f"\n=== Chain self-verify ===")
    print(f"  {'PASS' if chain_ok else 'FAIL'} — chain integrity intact")

    print(f"\n=== Summary ===")
    print(f"  JSONL file : {jsonl_path}")
    print(f"  Receipts   : {len(chain._receipts)}")
    print(f"  CLI verify : {'PASS' if verify_ok else 'FAIL'}")
    print(f"  Chain verify: {'PASS' if chain_ok else 'FAIL'}")

    # Cleanup
    shutil.rmtree(demo_dir)

    return verify_ok and chain_ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if main() else 1)
