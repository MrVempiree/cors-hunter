"""Command-line interface for cors-hunter."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import report
from .scanner import scan_urls


def load_targets(args: argparse.Namespace) -> List[str]:
    targets = list(args.targets or [])
    if args.file:
        with open(args.file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    return targets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cors-hunter",
        description="Scan URLs for CORS misconfigurations. "
                    "Authorised testing only — scan systems you own or "
                    "have explicit permission to test.",
    )
    parser.add_argument("targets", nargs="*", help="Target URL(s) to scan")
    parser.add_argument("-f", "--file",
                        help="File with one target URL per line")
    parser.add_argument("--format", choices=["terminal", "json", "markdown"],
                        default="terminal", help="Report format")
    parser.add_argument("-o", "--output", help="Write the report to a file")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium",
                                              "low", "never"],
                        default="high",
                        help="Exit non-zero when a finding at or above this "
                             "severity exists (default: high)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    targets = load_targets(args)
    if not targets:
        parser.error("no targets given (pass URLs or --file)")

    findings = scan_urls(targets)

    if args.format == "json":
        output = report.to_json(findings)
    elif args.format == "markdown":
        output = report.to_markdown(findings)
    else:
        output = report.to_terminal(findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output + "\n")
    else:
        print(output)

    if args.fail_on == "never":
        return 0
    from .scanner import SEVERITY_ORDER
    threshold = SEVERITY_ORDER[args.fail_on]
    worst = max((SEVERITY_ORDER[f.severity] for f in findings), default=-1)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
