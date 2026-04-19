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

from agentledger.dashboard.reader import AgentSummary, ReceiptRow, read_receipts, scan_agents

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


@app.get("/agents/{agent_id}", response_class=HTMLResponse)
def agent_timeline_page(request: Request, agent_id: str):
    storage = _require_storage()
    agents = scan_agents(storage)
    agent = next((a for a in agents if a.agent_id == agent_id), None)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
    receipts = read_receipts(agent.jsonl_path)
    return templates.TemplateResponse("timeline.html", {
        "request": request,
        "agent": agent,
        "receipts": receipts,
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
    }
