"""
agentledger verify <path>
=======================
Verify the tamper-evidence of one or more receipt chain files.

Usage:
    agentledger verify ./receipts/agent1_2026-04-18_abc.jsonl
    agentledger verify ./receipts/  --checkpoint-only

Exit codes:
    0 = chain valid
    1 = verification failed
    2 = invalid usage / file not found
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterator

# The verify logic lives in ReceiptChain — we import the protocol.
# Concrete implementation is provided by core (claude/core).
# For CLI standalone use we need a minimal verifier that does NOT
# require the core implementation — it verifies raw JSONL only.


def iter_jsonl(path: Path) -> Iterator[dict]:
    """Yield parsed JSON objects from a .jsonl file."""
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{line_no}: invalid JSON — {e}")


def compute_sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def canonicalise(obj: dict) -> bytes:
    """
    Serialize dict to canonical JSON: keys sorted lexicographically,
    no extra whitespace.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_receipt_chain(
    path: Path,
    *,
    checkpoint_only: bool = False,
    agent_public_key: bytes | None = None,
) -> tuple[bool, str]:
    """
    Verify a single receipt chain file.

    Args:
        path: Path to .jsonl file.
        checkpoint_only: If True, only verify from nearest checkpoint.
        agent_public_key: Ed25519 public key (32 bytes) to verify signatures.
                          If None, signature verification is skipped.

    Returns:
        (is_valid, human_message)
    """
    receipts: list[dict] = list(iter_jsonl(path))

    if not receipts:
        return True, f"{path}: empty chain (ok)"

    # Separate checkpoints from receipts
    checkpoints: list[dict] = []
    data_receipts: list[dict] = []

    for r in receipts:
        if r.get("checkpoint"):
            checkpoints.append(r)
        else:
            data_receipts.append(r)

    if checkpoint_only and checkpoints:
        # Find the last checkpoint
        ckpt = checkpoints[-1]
        ckpt_receipt_count = ckpt.get("receipt_count", 0)
        # Verify cumulative hash of receipts 1..N
        batch = data_receipts[:ckpt_receipt_count]
        cumulative = b"".join(canonicalise(r) for r in batch)
        expected_cumulative = compute_sha256_hex(cumulative)
        if ckpt.get("cumulative_hash") != expected_cumulative:
            return False, (
                f"{path}: checkpoint cumulative hash mismatch at {ckpt.get('at_receipt_id')}"
            )
        # Walk only the tail
        tail = data_receipts[ckpt_receipt_count:]
        prev_receipt = batch[-1] if batch else None
        return _verify_tail(tail, prev_receipt, agent_public_key, path)

    # Full verification
    return _verify_full(data_receipts, checkpoints, agent_public_key, path)


def _verify_full(
    receipts: list[dict],
    checkpoints: list[dict],
    agent_public_key: bytes | None,
    path: Path,
) -> tuple[bool, str]:
    """Verify entire chain from genesis."""
    prev_receipt: dict | None = None
    prev_hash: str | None = None

    for i, receipt in enumerate(receipts):
        # Verify prev_hash linkage
        expected_prev = prev_hash
        actual_prev = receipt.get("prev_hash")
        if actual_prev != expected_prev:
            return False, (
                f"{path}:{i+1}: prev_hash mismatch — expected {expected_prev}, got {actual_prev}"
            )

        # Verify Ed25519 signature if key provided
        if agent_public_key:
            sig_hex = receipt.get("signature")
            if not sig_hex:
                return False, f"{path}:{i+1}: missing signature"
            try:
                from nacl.signing import VerifyKey
                from nacl.encoding import HexEncoder
            except ImportError:
                return False, (
                    f"{path}: requires PyNaCl for signature verification. "
                    "Install: pip install agentledger[crypto]"
                )
            try:
                vk = VerifyKey(agent_public_key, encoder=HexEncoder)
                # Build signing payload = receipt without signature field
                receipt_for_signing = {k: v for k, v in receipt.items() if k != "signature"}
                payload_bytes = canonicalise(receipt_for_signing)
                vk.verify(payload_bytes, sig_hex, encoder=HexEncoder)
            except Exception as e:
                return False, f"{path}:{i+1}: signature verification failed — {e}"

        # Compute prev_hash for next iteration
        prev_hash = compute_sha256_hex(canonicalise(receipt))
        prev_receipt = receipt

    # Verify checkpoint cumulative hashes
    for ckpt in checkpoints:
        # Find the batch this checkpoint covers
        at_id = ckpt.get("at_receipt_id")
        idx = next((i for i, r in enumerate(receipts) if r.get("receipt_id") == at_id), None)
        if idx is None:
            return False, f"{path}: checkpoint at {at_id} references unknown receipt"
        batch = receipts[: idx + 1]
        cumulative = b"".join(canonicalise(r) for r in batch)
        expected = compute_sha256_hex(cumulative)
        if ckpt.get("cumulative_hash") != expected:
            return False, (
                f"{path}: checkpoint {at_id}: cumulative hash mismatch"
            )

    return True, f"{path}: {len(receipts)} receipts verified — chain valid"


def _verify_tail(
    tail: list[dict],
    prev_receipt: dict | None,
    agent_public_key: bytes | None,
    path: Path,
) -> tuple[bool, str]:
    """Verify only the tail from the last checkpoint."""
    prev_hash = compute_sha256_hex(canonicalise(prev_receipt)) if prev_receipt else None

    for i, receipt in enumerate(tail):
        expected_prev = prev_hash
        actual_prev = receipt.get("prev_hash")
        if actual_prev != expected_prev:
            return False, (
                f"{path}: tail:{i+1}: prev_hash mismatch — expected {expected_prev}"
            )
        prev_hash = compute_sha256_hex(canonicalise(receipt))

    return True, f"{path}: {len(tail)} tail receipts verified (from checkpoint)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify AgentLedger receipt chain files."
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to .jsonl file or directory containing .jsonl files.",
    )
    parser.add_argument(
        "--checkpoint-only",
        action="store_true",
        help="Verify only from nearest checkpoint (faster for large chains).",
    )
    parser.add_argument(
        "--agent-public-key",
        type=str,
        help="Ed25519 public key hex for signature verification.",
    )
    args = parser.parse_args(argv)

    # Parse public key if provided
    agent_public_key: bytes | None = None
    if args.agent_public_key:
        hex_str = args.agent_public_key.lower().replace("0x", "")
        if len(hex_str) != 64:
            print(
                f"Error: --agent-public-key must be 64 hex chars (32 bytes)",
                file=sys.stderr,
            )
            return 2
        try:
            agent_public_key = bytes.fromhex(hex_str)
        except ValueError as e:
            print(f"Error: invalid hex — {e}", file=sys.stderr)
            return 2

    # Collect files
    if args.path.is_file():
        files = [args.path]
    elif args.path.is_dir():
        files = sorted(args.path.glob("*.jsonl"))
        files = [f for f in files if not f.name.endswith(".deleted")]
    else:
        print(f"Error: {args.path} not found", file=sys.stderr)
        return 2

    if not files:
        print(f"Warning: no .jsonl files found in {args.path}", file=sys.stderr)
        return 0

    all_ok = True
    for f in files:
        ok, msg = verify_receipt_chain(
            f,
            checkpoint_only=args.checkpoint_only,
            agent_public_key=agent_public_key,
        )
        print(msg)
        if not ok:
            all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
