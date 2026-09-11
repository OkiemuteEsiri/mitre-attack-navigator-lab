from __future__ import annotations

from .coverage_engine import metrics
from .models import CoverageFinding, TechniqueCoverage


def render_markdown(records: list[TechniqueCoverage], findings: list[CoverageFinding]) -> str:
    summary = metrics(records, findings)
    lines = [
        "# ATT&CK Coverage Assessment",
        "",
        "## Executive Summary",
        "",
        f"- Techniques assessed: **{summary['techniques']}**",
        f"- Fully covered applicable techniques: **{summary['coverage_pct']}%**",
        f"- Open findings: **{summary['open_findings']}**",
        f"- High-priority findings (score >= 80): **{summary['high_priority_findings']}**",
        "",
        "## Prioritized Findings",
        "",
        "| Score | Severity | Technique | Finding |",
        "|---:|---|---|---|",
    ]
    for finding in findings:
        lines.append(f"| {finding.score} | {finding.severity} | {finding.technique_id} | {finding.title} |")
    lines.extend(["", "## Remediation and Validation", ""])
    for finding in findings:
        lines.extend([
            f"### {finding.finding_id} — {finding.technique_id}",
            "",
            f"**Rationale:** {finding.rationale}",
            "",
            f"**Remediation:** {finding.remediation}",
            "",
        ])
    lines.extend([
        "## Interpretation",
        "",
        "ATT&CK mappings describe defensive threat-model coverage. They do not assert that an intrusion occurred, and a mapped analytic is not considered validated until repeatable evidence is captured.",
        "",
    ])
    return "\n".join(lines)
