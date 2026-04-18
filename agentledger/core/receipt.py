"""
core/receipt.py — Receipt serialisation, canonical hashing, SHA-256 helper.
Implements the stubs declared in interfaces.py.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from agentledger.interfaces import ActionData, CrossAgentRef, Receipt


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sort_dict(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _sort_dict(v) for k in sorted(obj)}
    if isinstance(obj, list):
        return [_sort_dict(i) for i in obj]
    return obj


def _action_to_dict(action: ActionData) -> dict[str, Any]:
    return {
        "error": action.error,
        "framework": action.framework.value,
        "payload_hash": action.payload_hash,
        "result_hash": action.result_hash,
        "status": action.status.value,
        "tool_name": action.tool_name,
        "type": action.type.value,
    }


def _cross_ref_to_dict(ref: CrossAgentRef | None) -> dict[str, Any] | None:
    if ref is None:
        return None
    return ref.to_dict()


def receipt_to_dict(receipt: Receipt, *, include_signature: bool = True) -> dict[str, Any]:
    d: dict[str, Any] = {
        "action": _action_to_dict(receipt.action),
        "agent_id": receipt.agent_id,
        "chain_id": receipt.chain_id,
        "cross_agent_ref": _cross_ref_to_dict(receipt.cross_agent_ref),
        "prev_hash": receipt.prev_hash,
        "principal_id": receipt.principal_id,
        "receipt_id": receipt.receipt_id,
        "schema_version": receipt.schema_version,
        "timestamp": receipt.timestamp,
    }
    if include_signature:
        d["signature"] = receipt.signature
    return _sort_dict(d)


def canonicalise_for_signing(receipt: Receipt) -> bytes:
    """Deterministic UTF-8 bytes of receipt excluding the signature field."""
    d = receipt_to_dict(receipt, include_signature=False)
    return json.dumps(d, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()
