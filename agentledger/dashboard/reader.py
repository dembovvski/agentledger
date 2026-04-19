"""
dashboard/reader.py — JSONL scanning and receipt parsing for the dashboard.

Scans a storage directory for agent JSONL files and converts raw dicts
into typed models the API can serve directly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class ReceiptRow:
    receipt_id: str
    timestamp: str
    action_type: str
    framework: str
    tool_name: Optional[str]
    status: str
    payload_hash: Optional[str]
    result_hash: Optional[str]
    error: Optional[str]
    prev_hash: Optional[str]
    signature: Optional[str]
    cross_agent_ref: Optional[dict]
    agent_id: str = ""          # chain owner — used for back-link in detail view
    chain_id: str = ""          # same as agent_id for single-agent chains
    principal_id: str = ""     # principal binding
    schema_version: str = "0.1"

    @property
    def status_class(self) -> str:
        """CSS class for colour-coding in the template."""
        return {
            "completed": "status-completed",
            "failed": "status-failed",
            "denied": "status-denied",
            "pending": "status-pending",
        }.get(self.status, "status-unknown")

    @property
    def short_id(self) -> str:
        return self.receipt_id[:8]

    @property
    def short_prev(self) -> Optional[str]:
        return self.prev_hash[:8] if self.prev_hash else None

    @property
    def has_cross_ref(self) -> bool:
        return self.cross_agent_ref is not None


@dataclass
class AgentSummary:
    agent_id: str
    jsonl_path: Path
    receipt_count: int
    last_seen: Optional[str]
    chain_valid: bool
    chain_error: Optional[str]

    @property
    def short_id(self) -> str:
        return self.agent_id[:16]

    @property
    def status_class(self) -> str:
        return "status-completed" if self.chain_valid else "status-failed"


def _parse_receipt(obj: dict) -> Optional[ReceiptRow]:
    """Convert a raw JSONL dict to ReceiptRow. Returns None for checkpoints."""
    if obj.get("checkpoint"):
        return None
    action = obj.get("action", {})
    cross = obj.get("cross_agent_ref")
    return ReceiptRow(
        receipt_id=obj.get("receipt_id", ""),
        timestamp=obj.get("timestamp", ""),
        action_type=action.get("type", ""),
        framework=action.get("framework", ""),
        tool_name=action.get("tool_name"),
        status=action.get("status", ""),
        payload_hash=action.get("payload_hash"),
        result_hash=action.get("result_hash"),
        error=action.get("error"),
        prev_hash=obj.get("prev_hash"),
        signature=obj.get("signature"),
        cross_agent_ref=cross if cross and any(cross.values()) else None,
        agent_id=obj.get("agent_id", ""),
        chain_id=obj.get("chain_id", ""),
        principal_id=obj.get("principal_id", ""),
        schema_version=obj.get("schema_version", "0.1"),
    )


def read_receipts(jsonl_path: Path) -> list[ReceiptRow]:
    """Read all receipts from a JSONL file (skips checkpoints)."""
    rows: list[ReceiptRow] = []
    try:
        with jsonl_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    row = _parse_receipt(obj)
                    if row is not None:
                        rows.append(row)
                except (json.JSONDecodeError, KeyError):
                    continue
    except OSError:
        pass
    return rows


def scan_agents(storage_path: Path) -> list[AgentSummary]:
    """
    Scan storage_path for *.jsonl files and build AgentSummary for each.

    Files are grouped by agent_id (extracted from chain_id field in receipts).
    Multiple files from the same agent (multiple sessions) are merged.
    """
    from agentledger.cli.verify import verify_receipt_chain

    # Group files by agent_id
    file_agent: dict[str, Path] = {}  # agent_id → latest file
    for jsonl_file in sorted(storage_path.glob("*.jsonl")):
        rows = read_receipts(jsonl_file)
        if rows:
            # Use first receipt's agent context from filename prefix
            agent_id = _extract_agent_id(jsonl_file, rows)
            if agent_id:
                # Keep latest file per agent (sorted glob gives oldest first)
                file_agent[agent_id] = jsonl_file

    summaries: list[AgentSummary] = []
    for agent_id, jsonl_file in file_agent.items():
        rows = read_receipts(jsonl_file)
        last_seen = rows[-1].timestamp if rows else None

        # Verify chain
        try:
            ok, err = verify_receipt_chain(
                jsonl_file,
                agent_public_key=bytes.fromhex(agent_id),
            )
            chain_valid = ok
            chain_error = None if ok else err
        except Exception as e:
            chain_valid = False
            chain_error = str(e)

        summaries.append(AgentSummary(
            agent_id=agent_id,
            jsonl_path=jsonl_file,
            receipt_count=len(rows),
            last_seen=last_seen,
            chain_valid=chain_valid,
            chain_error=chain_error,
        ))

    return sorted(summaries, key=lambda s: s.last_seen or "", reverse=True)


def _extract_agent_id(jsonl_file: Path, rows: list[ReceiptRow]) -> Optional[str]:
    """Extract agent_id from JSONL by reading raw chain_id field."""
    try:
        with jsonl_file.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if not obj.get("checkpoint") and obj.get("agent_id"):
                    return obj["agent_id"]
    except (OSError, json.JSONDecodeError):
        pass
    return None


def get_receipt_by_id(storage_path: Path, receipt_id: str) -> tuple[Optional[ReceiptRow], Optional[Path]]:
    """
    Find a receipt by ID across all JSONL files in storage_path.

    Returns (receipt_row, jsonl_path) or (None, None) if not found.
    """
    for jsonl_file in sorted(storage_path.glob("*.jsonl")):
        rows = read_receipts(jsonl_file)
        for row in rows:
            if row.receipt_id == receipt_id:
                return row, jsonl_file
    return None, None
