from __future__ import annotations

import argparse
from collections.abc import Mapping
import json
from pathlib import Path
import sys
from typing import Any

from agent_audit_kit import __version__
from agent_audit_kit.audit import audit_candidate
from agent_audit_kit.models import CONTRACT_VERSION, AuditConfig, PreflightPolicy
from agent_audit_kit.preflight import preflight_task


EXIT_OK = 0
EXIT_REVIEW = 2
EXIT_BLOCKED = 3
EXIT_INVALID_INPUT = 4


def _load_mapping(path: str) -> dict[str, Any]:
    if path == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(path).read_text(encoding="utf-8")
    value = json.loads(raw)
    if not isinstance(value, Mapping):
        raise ValueError(f"{path} must contain a JSON object")
    return dict(value)


def _write_json(value: Mapping[str, Any], *, stream=None) -> None:
    print(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False),
        file=stream or sys.stdout,
    )


def _status_exit(status: str) -> int:
    if status in {"allowed", "approved_candidate"}:
        return EXIT_OK
    if status in {"needs_approval", "needs_review"}:
        return EXIT_REVIEW
    return EXIT_BLOCKED


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tamvi-agent-gate",
        description="Versioned preflight and candidate-release gate for mapping-shaped agent packets.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    preflight = commands.add_parser("preflight", help="Evaluate an envelope before worker execution.")
    preflight.add_argument("--envelope", required=True, help="Envelope JSON file, or - for stdin.")
    preflight.add_argument("--policy", required=True, help="Policy JSON file.")

    audit = commands.add_parser("audit", help="Audit a candidate packet after worker execution.")
    audit.add_argument("--candidate", required=True, help="Candidate JSON file, or - for stdin.")
    audit.add_argument("--verified", help="Verified-evidence JSON file.")
    audit.add_argument("--envelope", help="Trusted envelope JSON file.")
    audit.add_argument("--policy", help="Policy JSON file.")
    audit.add_argument(
        "--allow-missing-claimed",
        action="store_true",
        help="Do not require worker-claimed sources/checks.",
    )
    audit.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Compatibility mode only; still routes the candidate to review.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "preflight":
            envelope = _load_mapping(args.envelope)
            policy = PreflightPolicy.from_mapping(_load_mapping(args.policy))
            result = preflight_task(envelope, policy)
            _write_json(result.to_dict())
            return _status_exit(result.status)

        candidate = _load_mapping(args.candidate)
        verified = _load_mapping(args.verified) if args.verified else None
        envelope = _load_mapping(args.envelope) if args.envelope else None
        policy = (
            PreflightPolicy.from_mapping(_load_mapping(args.policy))
            if args.policy
            else None
        )
        config = AuditConfig(
            require_claimed_evidence=not args.allow_missing_claimed,
            require_verified_evidence=not args.allow_unverified,
        )
        result = audit_candidate(
            candidate,
            config=config,
            verified_evidence=verified,
            envelope=envelope,
            policy=policy,
        )
        _write_json(result.to_dict())
        return _status_exit(result.status)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        _write_json(
            {
                "contract_version": CONTRACT_VERSION,
                "status": "invalid_input",
                "error": str(exc),
            },
            stream=sys.stderr,
        )
        return EXIT_INVALID_INPUT
