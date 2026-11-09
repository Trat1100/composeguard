from __future__ import annotations

import argparse
import json
import sys

from composeguard.scanner import ComposeFileError, SEVERITY_ORDER, scan_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="composeguard", description="Static security and reliability checks for Docker Compose files.")
    parser.add_argument("file", help="Path to compose.yaml or docker-compose.yml")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Report format")
    parser.add_argument("--fail-on", choices=("none", "info", "warning", "critical"), default="warning", help="Exit with status 1 when a finding at this severity or above is present")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = scan_file(args.file)
    except ComposeFileError as exc:
        print(f"composeguard: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        counts = report.counts()
        print(f"ComposeGuard report: {report.source}")
        print(f"Findings: {counts['critical']} critical, {counts['warning']} warning, {counts['info']} info")
        for finding in report.findings:
            print(f"[{finding.severity.upper()}] {finding.rule_id} at {finding.location}: {finding.message}")
        if not report.findings:
            print("No findings.")

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return int(any(SEVERITY_ORDER[item.severity] >= threshold for item in report.findings))


if __name__ == "__main__":
    raise SystemExit(main())
