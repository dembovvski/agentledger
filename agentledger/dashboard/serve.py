"""CLI entry point: agentledger dashboard --storage ./receipts --port 8000"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AgentLedger compliance dashboard")
    parser.add_argument(
        "--storage",
        type=Path,
        required=True,
        help="Path to directory containing agent JSONL files",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true", help="Auto-reload on file change")
    args = parser.parse_args(argv)

    try:
        import uvicorn
    except ImportError:
        print("Dashboard requires uvicorn. Install: pip install 'agentledger[dashboard]'", file=sys.stderr)
        return 1

    from agentledger.dashboard.api import app, configure
    configure(args.storage)

    print(f"AgentLedger Dashboard → http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
