from __future__ import annotations

import argparse
from pathlib import Path

from .coverage_engine import assess
from .loader import load_coverage
from .report import render_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess synthetic MITRE ATT&CK detection coverage")
    parser.add_argument("input", help="Path to coverage JSON")
    parser.add_argument("--report", help="Optional Markdown output path")
    args = parser.parse_args()

    records = load_coverage(args.input)
    findings = assess(records)
    report = render_markdown(records, findings)
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
