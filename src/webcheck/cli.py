"""Command line entry point."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .capture import capture_all
from .compare import classify, classify_all
from .inputs import InputError, parse_hosts
from .models import Pair, read_results, write_results
from .report import build_report

_MARK = {
    "differs": "DIFFERS ",
    "cert-err": "cert-err",
    "unreachable": "down    ",
    "same": "same    ",
    "unknown": "?       ",
}


def _progress(pair: Pair) -> None:
    classify(pair)
    print(f"  {_MARK.get(pair.verdict, '?')}  {pair.hostname} ({pair.ip})", file=sys.stderr)


def _run_capture(args) -> int:
    try:
        targets = parse_hosts(args.hosts)
    except (InputError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Capturing {len(targets)} host(s) -> {args.out}", file=sys.stderr)
    pairs = asyncio.run(
        capture_all(
            targets,
            args.out,
            concurrency=args.concurrency,
            timeout_ms=args.timeout * 1000,
            on_done=_progress,
        )
    )
    pairs = classify_all(pairs)
    write_results(pairs, args.out)

    if not args.no_report:
        report = build_report(pairs, args.out)
        print(f"\nReport: {report}", file=sys.stderr)

    flagged = sum(1 for p in pairs if p.verdict == "differs")
    print(f"{flagged} of {len(pairs)} pair(s) flagged as differing.", file=sys.stderr)
    return 0


def _run_report(args) -> int:
    try:
        pairs = read_results(args.out)
    except (OSError, KeyError, ValueError) as exc:
        print(f"error: cannot read {args.out}/results.json: {exc}", file=sys.stderr)
        return 2
    pairs = classify_all(pairs)
    write_results(pairs, args.out)
    report = build_report(pairs, args.out)
    print(f"Report: {report}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webcheck",
        description="Render each host by hostname and by IP, then compare the two.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    cap = sub.add_parser("capture", help="render every host and write results + report")
    cap.add_argument("hosts", type=Path, help="CSV file of hostname,ip rows")
    cap.add_argument("-o", "--out", type=Path, default=Path("out"), help="output directory")
    cap.add_argument("-c", "--concurrency", type=int, default=4, help="parallel hosts")
    cap.add_argument("-t", "--timeout", type=int, default=20, help="per-page timeout, seconds")
    cap.add_argument("--no-report", action="store_true", help="skip HTML generation")
    cap.set_defaults(func=_run_capture)

    rep = sub.add_parser("report", help="rebuild the HTML report from an existing results.json")
    rep.add_argument("-o", "--out", type=Path, default=Path("out"), help="output directory")
    rep.set_defaults(func=_run_report)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    raise SystemExit(args.func(args))
