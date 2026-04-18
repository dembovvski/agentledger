"""
core/chain.py — Thread-safe append-only receipt chain with JSONL storage
and optional checkpoint hashes.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from agentledger.interfaces import (
    ActionData,
    ActionStatus,
    ActionType,
    ChainVerificationError,
    CrossAgentRef,
    Framework,
    Receipt,
    ReceiptChain as ReceiptChainABC,
)
from agentledger.core.receipt import (
    canonicalise_for_signing,
    receipt_to_dict,
    sha256_hex,
)


class ReceiptChainImpl(ReceiptChainABC):
    def __init__(
        self,
        identity: Any,
        *,
        storage_path: str,
        checkpoint_interval: int = 100,
    ) -> None:
        super().__init__(identity, storage_path=storage_path, checkpoint_interval=checkpoint_interval)
        self._lock = threading.RLock()
        self._receipts: list[Receipt] = []
        self._pending: Optional[Receipt] = None
        self._log_path = Path(storage_path)
        self._log_path.mkdir(parents=True, exist_ok=True)
        agent_short = identity.agent_id[:8]
        date = datetime.now(timezone.utc).strftime("%Y%m%d")
        session = uuid.uuid4().hex[:8]
        self._log_file = self._log_path / f"{agent_short}_{date}_{session}.jsonl"

    # ── ABC property ──────────────────────────────────────────────────────────

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _prev_hash(self) -> Optional[str]:
        if not self._receipts:
            return None
        last = self._receipts[-1]
        return sha256_hex(canonicalise_for_signing(last))

    def _sign_receipt(self, receipt: Receipt) -> Receipt:
        payload = canonicalise_for_signing(receipt)
        sig = self.identity.sign(payload)
        receipt.signature = sig.hex()
        return receipt

    def _write_line(self, obj: dict[str, Any]) -> None:
        with self._log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n")

    def _maybe_checkpoint(self) -> None:
        n = len(self._receipts)
        if n > 0 and n % self.checkpoint_interval == 0:
            batch = self._receipts[-self.checkpoint_interval :]
            cumulative = sha256_hex(
                b"".join(canonicalise_for_signing(r) for r in batch)
            )
            cp: dict[str, Any] = {
                "at_receipt_id": batch[-1].receipt_id,
                "checkpoint": True,
                "cumulative_hash": cumulative,
                "receipt_count": n,
            }
            sig = self.identity.sign(
                json.dumps(cp, separators=(",", ":"), sort_keys=True).encode()
            )
            cp["signature"] = sig.hex()
            self._write_line(cp)

    # ── Public API ────────────────────────────────────────────────────────────

    def append(
        self,
        action_type: ActionType,
        framework: Framework,
        *,
        tool_name: Optional[str] = None,
        payload: Any = None,
        cross_agent_ref: Optional[CrossAgentRef] = None,
    ) -> str:
        with self._lock:
            # Orphaned pending receipt (never finalised) gets force-failed.
            if self._pending is not None:
                self._pending.action.status = ActionStatus.FAILED
                self._pending.action.error = "orphaned — next append called before finalize_last"
                self._sign_receipt(self._pending)
                self._receipts.append(self._pending)
                self._write_line(receipt_to_dict(self._pending))
                self._maybe_checkpoint()
                self._pending = None

            payload_hash: Optional[str] = None
            if payload is not None:
                raw = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str).encode()
                payload_hash = sha256_hex(raw)

            receipt = Receipt(
                receipt_id=str(uuid.uuid4()),
                chain_id=self.identity.agent_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent_id=self.identity.agent_id,
                principal_id=self.identity.principal_id,
                action=ActionData(
                    type=action_type,
                    framework=framework,
                    tool_name=tool_name,
                    status=ActionStatus.PENDING,
                    payload_hash=payload_hash,
                ),
                prev_hash=self._prev_hash(),
                cross_agent_ref=cross_agent_ref,
            )
            self._pending = receipt
            return receipt.receipt_id

    def finalize_last(
        self,
        *,
        status: ActionStatus,
        result: Any = None,
        error: Optional[str] = None,
    ) -> None:
        with self._lock:
            if self._pending is None:
                return

            self._pending.action.status = status
            if result is not None:
                raw = json.dumps(result, separators=(",", ":"), sort_keys=True, default=str).encode()
                self._pending.action.result_hash = sha256_hex(raw)
            if error is not None:
                self._pending.action.error = error

            self._sign_receipt(self._pending)
            self._receipts.append(self._pending)
            self._write_line(receipt_to_dict(self._pending))
            self._maybe_checkpoint()
            self._pending = None

    # ── Verification ──────────────────────────────────────────────────────────

    def verify(self, *, checkpoint_only: bool = False) -> bool:
        with self._lock:
            receipts = list(self._receipts)

        prev_hash: Optional[str] = None
        for i, receipt in enumerate(receipts):
            # 1. Check prev_hash linkage
            if receipt.prev_hash != prev_hash:
                raise ChainVerificationError(
                    f"Chain broken at receipt {receipt.receipt_id}: "
                    f"expected prev_hash={prev_hash}, got {receipt.prev_hash}"
                )
            # 2. Verify Ed25519 signature
            if receipt.signature is None:
                raise ChainVerificationError(f"Missing signature on receipt {receipt.receipt_id}")
            canon = canonicalise_for_signing(receipt)
            sig_bytes = bytes.fromhex(receipt.signature)
            if not self.identity.verify_signature(canon, sig_bytes):
                raise ChainVerificationError(f"Invalid signature on receipt {receipt.receipt_id}")

            prev_hash = sha256_hex(canon)

        return True

    # ── Retrieval ─────────────────────────────────────────────────────────────

    def get_receipt(self, receipt_id: str) -> Receipt:
        with self._lock:
            for r in self._receipts:
                if r.receipt_id == receipt_id:
                    return r
        raise KeyError(receipt_id)

    def iter_receipts(self) -> list[Receipt]:
        with self._lock:
            return list(self._receipts)
