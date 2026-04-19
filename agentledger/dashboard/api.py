"""
dashboard/api.py — FastAPI application for the AgentLedger compliance dashboard.

Usage:
    agentledger dashboard --storage ./receipts --port 8000

Routes:
    GET /                       → redirect to /agents
    GET /agents                 → agent list page
    GET /agents/{agent_id}      → receipt timeline for one agent
    GET /api/agents             → JSON: list of agent summaries
    GET /api/agents/{agent_id}  → JSON: receipts for one agent
    GET /api/verify/{agent_id}  → JSON: live chain verification result
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
    from fastapi.templating import Jinja2Templates
except ImportError as e:
    raise ImportError(
        "Dashboard requires fastapi and jinja2. "
        "Install: pip install 'agentledger[dashboard]'"
    ) from e

from agentledger.dashboard.reader import AgentSummary, ReceiptRow, read_receipts, scan_agents, get_receipt_by_id

app = FastAPI(title="AgentLedger Dashboard", docs_url=None, redoc_url=None)

# Templates directory — populated by Hermes's frontend work
_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# Storage path set at startup via configure()
_storage_path: Optional[Path] = None


def configure(storage_path: str | Path) -> None:
    """Set the storage directory before serving. Called by CLI entry point."""
    global _storage_path
    _storage_path = Path(storage_path)
    if not _storage_path.exists():
        raise ValueError(f"Storage path does not exist: {_storage_path}")


def _require_storage() -> Path:
    if _storage_path is None:
        raise RuntimeError("Dashboard not configured — call configure(storage_path) first")
    return _storage_path


# ── HTML routes ───────────────────────────────────────────────────────────────

@app.get("/", response_class=RedirectResponse)
def root():
    return RedirectResponse(url="/agents")


@app.get("/agents", response_class=HTMLResponse)
def agents_page(request: Request):
    storage = _require_storage()
    agents = scan_agents(storage)
    return templates.TemplateResponse("agents.html", {
        "request": request,
        "agents": agents,
        "storage_path": str(storage),
    })


@app.get("/timeline", response_class=HTMLResponse)
def timeline_page(request: Request):
    """
    Global cross-agent timeline — all receipts from all agents, chronologically.
    """
    storage = _require_storage()
    agents = scan_agents(storage)

    # Collect all receipts across all agent files
    all_receipts: list[ReceiptRow] = []
    for agent in agents:
        all_receipts.extend(read_receipts(agent.jsonl_path))

    # Sort chronologically
    all_receipts.sort(key=lambda r: r.timestamp)

    # Compute global stats
    stats = {"completed": 0, "failed": 0, "denied": 0, "pending": 0, "cross_agent": 0}
    for r in all_receipts:
        s = r.status
        if s == "completed":
            stats["completed"] += 1
        elif s == "failed":
            stats["failed"] += 1
        elif s == "denied":
            stats["denied"] += 1
        elif s == "pending":
            stats["pending"] += 1
        if r.has_cross_ref:
            stats["cross_agent"] += 1

    return templates.TemplateResponse("timeline.html", {
        "request": request,
        "agents": agents,
        "receipts": all_receipts,
        "stats": stats,
        "total_count": len(all_receipts),
    })


@app.get("/agents/{agent_id}", response_class=HTMLResponse)
def agent_detail_page(request: Request, agent_id: str):
    storage = _require_storage()
    agents = scan_agents(storage)
    agent = next((a for a in agents if a.agent_id == agent_id), None)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
    receipts = read_receipts(agent.jsonl_path)
    return templates.TemplateResponse("agent_detail.html", {
        "request": request,
        "agent": agent,
        "receipts": receipts,
    })


@app.get("/receipts/{receipt_id}", response_class=HTMLResponse)
def receipt_detail_page(request: Request, receipt_id: str):
    storage = _require_storage()
    receipt_row, jsonl_path = get_receipt_by_id(storage, receipt_id)
    if receipt_row is None:
        raise HTTPException(status_code=404, detail=f"Receipt {receipt_id} not found")

    # Verify chain
    from agentledger.cli.verify import verify_receipt_chain
    if jsonl_path:
        ok, msg = verify_receipt_chain(jsonl_path, agent_public_key=None)
        verify_result = {"valid": ok, "message": msg}
    else:
        verify_result = {"valid": False, "message": "Chain file not found"}

    return templates.TemplateResponse("receipt_detail.html", {
        "request": request,
        "receipt": receipt_row,
        "receipt_id": receipt_id,
        "verify_result": verify_result,
    })


# ── JSON API ──────────────────────────────────────────────────────────────────

@app.get("/api/agents")
def api_agents():
    storage = _require_storage()
    agents = scan_agents(storage)
    return [_agent_to_dict(a) for a in agents]


@app.get("/api/agents/{agent_id}/receipts")
def api_receipts(agent_id: str):
    storage = _require_storage()
    agents = scan_agents(storage)
    agent = next((a for a in agents if a.agent_id == agent_id), None)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
    receipts = read_receipts(agent.jsonl_path)
    return [_receipt_to_dict(r) for r in receipts]


@app.get("/api/agents/{agent_id}/verify")
def api_verify(agent_id: str):
    storage = _require_storage()
    agents = scan_agents(storage)
    agent = next((a for a in agents if a.agent_id == agent_id), None)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
    return {
        "agent_id": agent_id,
        "chain_valid": agent.chain_valid,
        "message": agent.chain_error or "chain valid",
    }


# ── Serialisation helpers ─────────────────────────────────────────────────────

def _agent_to_dict(a: AgentSummary) -> dict:
    return {
        "agent_id": a.agent_id,
        "short_id": a.short_id,
        "receipt_count": a.receipt_count,
        "last_seen": a.last_seen,
        "chain_valid": a.chain_valid,
        "chain_error": a.chain_error,
    }


def _receipt_to_dict(r: ReceiptRow) -> dict:
    return {
        "receipt_id": r.receipt_id,
        "timestamp": r.timestamp,
        "action_type": r.action_type,
        "framework": r.framework,
        "tool_name": r.tool_name,
        "status": r.status,
        "payload_hash": r.payload_hash,
        "result_hash": r.result_hash,
        "error": r.error,
        "prev_hash": r.prev_hash,
        "has_cross_ref": r.has_cross_ref,
        "cross_agent_ref": r.cross_agent_ref,
        "agent_id": r.agent_id,
        "chain_id": r.chain_id,
        "principal_id": r.principal_id,
    }
