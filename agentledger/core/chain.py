"""
core/chain.py — Thread-safe append-only receipt chain with JSONL storage
and optional checkpoint hashes.
"""

from __future__ import annotations

import copy
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from agentledger.interfaces import (
    ActionData,
    ActionPolicy,
    ActionStatus,
    ActionType,
    ChainVerificationError,
    CrossAgentRef,
    CrossAgentRefStatus,
    Framework,
    PolicyVerdict,
    PolicyViolationError,
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
        policy: Optional[ActionPolicy] = None,
    ) -> None:
        super().__init__(identity, storage_path=storage_path, checkpoint_interval=checkpoint_interval)
        self._policy = policy
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
            f.write(json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False) + "\n")

    def _maybe_checkpoint(self) -> None:
        n = len(self._receipts)
        if n > 0 and n % self.checkpoint_interval == 0:
            # Cumulative hash covers ALL receipts from genesis to now,
            # consistent with CLI which uses receipts[:receipt_count].
            batch = self._receipts
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
                json.dumps(cp, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()
            )
            cp["signature"] = sig.hex()
            self._write_line(cp)

    def _record_denied(
        self,
        action_type: ActionType,
        framework: Framework,
        tool_name: Optional[str],
        reason: str,
    ) -> None:
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
                status=ActionStatus.DENIED,
                error=f"policy:denied — {reason}",
                policy_hash=self._policy.policy_id if self._policy is not None else None,
            ),
            prev_hash=self._prev_hash(),
        )
        self._sign_receipt(receipt)
        self._receipts.append(receipt)
        self._write_line(receipt_to_dict(receipt))
        self._maybe_checkpoint()

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
            # Validate tool_name for TOOL_CALL actions
            if action_type == ActionType.TOOL_CALL and tool_name is None:
                raise ValueError("tool_name is required for ActionType.TOOL_CALL")

            # Pre-execution policy gate
            if self._policy is not None:
                policy_payload = str(payload) if payload is not None else None
                result = self._policy.evaluate(action_type, tool_name, policy_payload)
                if result.verdict == PolicyVerdict.DENY:
                    self._record_denied(action_type, framework, tool_name, result.reason)
                    raise PolicyViolationError(tool_name, result.reason)

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
                    policy_hash=self._policy.policy_id if self._policy is not None else None,
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
        """
        Verify in-memory chain integrity (hash linkage + Ed25519 signatures).

        IMPORTANT: This method checks only the in-memory receipt list — it does
        NOT read from disk. An attacker with write access to the JSONL file can
        rewrite it without this method detecting the change. Use verify_from_disk()
        for tamper detection of the persisted chain, or run:
            agentledger verify <path> --agent-public-key <hex>
        """
        with self._lock:
            receipts = list(self._receipts)

        if not receipts:
            raise ValueError("Cannot verify an empty chain — no receipts found")

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
                    return copy.deepcopy(r)
        raise KeyError(receipt_id)

    def iter_receipts(self) -> list[Receipt]:
        with self._lock:
            return [copy.deepcopy(r) for r in self._receipts]

    # ── Cross-agent reference management ─────────────────────────────────────────

    def confirm_cross_ref(self, receipt_id: str) -> str:
        """
        Confirm a PENDING cross-agent reference on an existing receipt.

        Flow:
        1. Find receipt with matching receipt_id
        2. Verify it has cross_agent_ref with status=PENDING
        3. Verify no CONFIRMATION receipt already exists for this receipt_id
           (append-only: we cannot edit the original, so we check the chain)
        4. Append a new receipt with ActionType=CROSS_AGENT, status=COMPLETED,
           and cross_agent_ref pointing to the original receipt + status=CONFIRMED
        """
        with self._lock:
            # Find the receipt
            target_receipt: Optional[Receipt] = None
            for r in self._receipts:
                if r.receipt_id == receipt_id:
                    target_receipt = r
                    break
            if target_receipt is None:
                raise KeyError(f"Receipt {receipt_id} not found in chain")

            ref = target_receipt.cross_agent_ref
            if ref is None:
                raise ValueError(f"Receipt {receipt_id} has no cross_agent_ref")
            if ref.status == CrossAgentRefStatus.CONFIRMED:
                raise ValueError(f"Cross-agent ref on {receipt_id} is already CONFIRMED")

            # Check no CONFIRMATION receipt already exists for this target receipt_id
            # (append-only: we cannot edit, so we must detect duplicates)
            # A CONFIRMATION receipt is one with action.type == CROSS_AGENT and
            # cross_agent_ref.ref_receipt_id pointing to the receipt being confirmed.
            for r in self._receipts:
                if (
                    r.action.type == ActionType.CROSS_AGENT
                    and r.cross_agent_ref is not None
                    and r.cross_agent_ref.ref_receipt_id == receipt_id
                    and r.cross_agent_ref.status == CrossAgentRefStatus.CONFIRMED
                ):
                    raise ValueError(f"Cross-agent ref on {receipt_id} is already CONFIRMED")

            # Build new confirmation receipt (append-only)
            # The CONFIRMATION receipt's ref_receipt_id points to the receipt
            # being confirmed (b_receipt_id), not to the external agent's receipt.
            # This makes duplicate detection straightforward.
            cross_ref = CrossAgentRef(
                target_agent_id=ref.target_agent_id,
                ref_receipt_id=receipt_id,  # points to b_receipt_id (the one being confirmed)
                status=CrossAgentRefStatus.CONFIRMED,
            )
            confirm_receipt = Receipt(
                receipt_id=str(uuid.uuid4()),
                chain_id=self.identity.agent_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent_id=self.identity.agent_id,
                principal_id=self.identity.principal_id,
                action=ActionData(
                    type=ActionType.CROSS_AGENT,
                    framework=Framework.CUSTOM,
                    status=ActionStatus.COMPLETED,
                    payload_hash=sha256_hex(receipt_id.encode()),
                    result_hash=None,
                    error=None,
                ),
                prev_hash=self._prev_hash(),
                cross_agent_ref=cross_ref,
            )
            self._sign_receipt(confirm_receipt)
            self._receipts.append(confirm_receipt)
            self._write_line(receipt_to_dict(confirm_receipt))
            self._maybe_checkpoint()
            return confirm_receipt.receipt_id

    def resolve_cross_ref(self, ref: CrossAgentRef) -> bool:
        """
        Resolve a cross-agent reference from another agent's chain.

        Reads the referenced agent's JSONL file directly from disk, verifies
        the Ed25519 signature on the specific receipt, and checks whether it
        is COMPLETED or CONFIRMED.

        target_agent_id is the Ed25519 public key hex of the referenced agent,
        used for signature verification — ensuring the receipt cannot be forged.
        """
        if ref.ref_receipt_id is None or ref.target_agent_id is None:
            return False

        try:
            target_pub_bytes = bytes.fromhex(ref.target_agent_id)
        except ValueError:
            return False

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        from agentledger.cli.verify import canonicalise

        log_dir = Path(self._log_path)
        for jsonl_file in log_dir.glob("*.jsonl"):
            # Match by scanning file content — avoids 8-char prefix collisions
            found_agent = False
            target_obj: Optional[dict] = None

            with jsonl_file.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if obj.get("checkpoint"):
                        continue
                    # Confirm this file belongs to the target agent
                    if not found_agent:
                        if obj.get("agent_id") == ref.target_agent_id:
                            found_agent = True
                        else:
                            break  # Wrong agent file
                    if obj.get("receipt_id") == ref.ref_receipt_id:
                        target_obj = obj
                        break

            if target_obj is None:
                continue

            # Verify Ed25519 signature on the specific receipt
            sig_hex = target_obj.get("signature")
            if not sig_hex:
                return False
            try:
                pub = Ed25519PublicKey.from_public_bytes(target_pub_bytes)
                receipt_for_signing = {k: v for k, v in target_obj.items() if k != "signature"}
                pub.verify(bytes.fromhex(sig_hex), canonicalise(receipt_for_signing))
            except (InvalidSignature, Exception):
                return False

            status = target_obj.get("action", {}).get("status")
            return status == "completed"

        return False

    def verify_from_disk(self) -> tuple[bool, str]:
        """
        Verify the persisted JSONL file against the Ed25519 public key.

        Unlike verify(), this reads from disk — catching tampering that happened
        after the chain was written (e.g. direct file edits).
        Returns (is_valid, human_message) — same contract as cli.verify.verify_receipt_chain.
        """
        from agentledger.cli.verify import verify_receipt_chain
        return verify_receipt_chain(
            self._log_file,
            agent_public_key=bytes.fromhex(self.identity.agent_id),
        )
