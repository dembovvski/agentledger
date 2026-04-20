"""
agentledger CLI
==============
Usage:
    agentledger verify <path>   [--checkpoint-only] [--agent-public-key HEX]
    agentledger inspect <path>  [--verbose]

Install the CLI:
    pip install -e .
    # or
    agentledger verify ...
    python -m agentledger.cli verify ...
"""

from __future__ import annotations

import argparse
import sys

from agentledger.cli import verify, inspect


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentledger",
        description="AgentLedger Protocol — open audit trail for multi-agent AI.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # verify
    verify_parser = sub.add_parser(
        "verify",
        help="Verify tamper-evidence of receipt chain files.",
    )
    verify_parser.add_argument(
        "path",
        help="Path to .jsonl file or directory.",
    )
    verify_parser.add_argument(
        "--checkpoint-only",
        action="store_true",
        help="Verify only from nearest checkpoint (faster).",
    )
    verify_parser.add_argument(
        "--agent-public-key",
        type=str,
        help="Ed25519 public key hex for signature verification.",
    )

    # inspect
    inspect_parser = sub.add_parser(
        "inspect",
        help="Human-readable summary of receipt chain files.",
    )
    inspect_parser.add_argument(
        "path",
        help="Path to .jsonl file or directory.",
    )
    inspect_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show full receipt details.",
    )

    args = parser.parse_args(argv)

    if args.command == "verify":
        fwd = [str(args.path)]
        if args.checkpoint_only:
            fwd.append("--checkpoint-only")
        if args.agent_public_key:
            fwd += ["--agent-public-key", args.agent_public_key]
        return verify.main(fwd)
    elif args.command == "inspect":
        fwd = [str(args.path)]
        if args.verbose:
            fwd.append("--verbose")
        return inspect.main(fwd)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
