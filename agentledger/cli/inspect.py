"""
agentledger inspect <path>
==========================
Human-readable summary of receipt chain(s).

Usage:
    agentledger inspect ./receipts/agent1_2026-04-18.jsonl
    agentledger inspect ./receipts/  --summary
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator


def iter_jsonl(path: Path) -> Iterator[dict]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def format_timestamp(ts: str) -> str:
    """Parse ISO8601 and return human-readable string."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return ts


def inspect_file(path: Path, *, verbose: bool = False) -> None:
    receipts = list(iter_jsonl(path))
    if not receipts:
        print(f"{path}: empty")
        return

    data_receipts = [r for r in receipts if not r.get("checkpoint")]
    checkpoints = [r for r in receipts if r.get("checkpoint")]

    print(f"{'='*70}")
    print(f"  File:  {path.name}")
    print(f"  Chain: {data_receipts[0].get('chain_id', '?')[:16]}...")
    print(f"  Agent: {data_receipts[0].get('agent_id', '?')[:16]}...")
    print(f"  Receipts:    {len(data_receipts)}")
    print(f"  Checkpoints: {len(checkpoints)}")
    print(f"{'='*70}")

    if not verbose:
        # Summary table
        print()
        print(
            f"{'receipt_id':<40} {'type':<14} {'tool':<20} {'status':<10} {'time':<26}"
        )
        print("-" * 110)
        for r in data_receipts:
            action = r.get("action", {})
            rid = r.get("receipt_id", "?")
            atype = action.get("type", "?")
            tool = action.get("tool_name", "—")
            status = action.get("status", "?")
            ts = format_timestamp(r.get("timestamp", "?"))
            print(f"{rid:<40} {atype:<14} {tool:<20} {status:<10} {ts:<26}")
        print()
        return

    # Verbose: full receipt details
    for i, r in enumerate(data_receipts):
        print(f"\n--- Receipt {i+1}/{len(data_receipts)} ---")
        print(f"  receipt_id:   {r.get('receipt_id')}")
        print(f"  timestamp:    {format_timestamp(r.get('timestamp', '?'))}")
        print(f"  prev_hash:    {r.get('prev_hash', 'null') or 'null'}")
        print(f"  agent_id:     {r.get('agent_id')}")
        print(f"  principal_id: {r.get('principal_id')}")
        action = r.get("action", {})
        print(f"  action.type:        {action.get('type')}")
        print(f"  action.framework:   {action.get('framework')}")
        print(f"  action.tool_name:   {action.get('tool_name', '—')}")
        print(f"  action.status:      {action.get('status')}")
        print(f"  action.payload_hash: {action.get('payload_hash')}")
        print(f"  action.result_hash:  {action.get('result_hash')}")
        if action.get("error"):
            print(f"  action.error:        {action.get('error')}")
        ref = r.get("cross_agent_ref")
        if ref and ref.get("target_agent_id"):
            print(f"  cross_agent_ref: {ref.get('target_agent_id')} [{ref.get('status')}]")
        print(f"  signature:      {r.get('signature', '?')[:32]}...")

    # Checkpoints section
    if checkpoints:
        print(f"\n--- Checkpoints ({len(checkpoints)}) ---")
        for ckpt in checkpoints:
            print(
                f"  receipt_id={ckpt.get('at_receipt_id')}  "
                f"count={ckpt.get('receipt_count')}  "
                f"hash={ckpt.get('cumulative_hash', '')[:16]}..."
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect AgentLedger receipt chains — human-readable summary."
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to .jsonl file or directory containing .jsonl files.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show full receipt details instead of summary table.",
    )
    parser.add_argument(
        "--summary", "-s",
        action="store_true",
        help="Show only per-file summary (default for directories).",
    )
    args = parser.parse_args(argv)

    if args.path.is_file():
        inspect_file(args.path, verbose=args.verbose)
    elif args.path.is_dir():
        files = sorted(args.path.glob("*.jsonl"))
        files = [f for f in files if not f.name.endswith(".deleted")]
        if not files:
            print(f"No .jsonl files found in {args.path}", file=sys.stderr)
            return 2
        for f in files:
            inspect_file(f, verbose=args.verbose)
            print()
    else:
        print(f"Error: {args.path} not found", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
