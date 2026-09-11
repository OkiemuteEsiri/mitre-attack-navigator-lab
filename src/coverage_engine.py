from __future__ import annotations

import hashlib
from collections import Counter

from .models import CoverageFinding, TechniqueCoverage

SEVERITY_BASE = {"critical": 90, "high": 75, "medium": 55, "low": 30}
STATUS_PENALTY = {"gap": 10, "partial": 5, "covered": -20, "not_applicable": -30}


def _finding_id(record: TechniqueCoverage, kind: str) -> str:
    payload = f"{record.technique_id}|{kind}|{record.owner}".encode()
    return "ATK-" + hashlib.sha256(payload).hexdigest()[:10].upper()


def assess(records: list[TechniqueCoverage]) -> list[CoverageFinding]:
    findings: list[CoverageFinding] = []
    for record in records:
        if record.status in {"covered", "not_applicable"}:
            continue
        score = SEVERITY_BASE[record.severity] + STATUS_PENALTY[record.status]
        if not record.data_sources:
            score += 5
        if not record.detections:
            score += 5
        if not record.validation_evidence.strip():
            score += 5
        score = max(0, min(100, score))
        gaps = []
        if not record.data_sources:
            gaps.append("required telemetry is undefined")
        if not record.detections:
            gaps.append("no detection analytic is mapped")
        if not record.validation_evidence.strip():
            gaps.append("validation evidence is missing")
        rationale = f"Coverage status is {record.status}." + (" " + "; ".join(gaps) + "." if gaps else "")
        remediation = "Map the required data source, implement or tune the analytic, capture repeatable validation evidence, and reassess coverage."
        findings.append(CoverageFinding(_finding_id(record, "coverage"), record.technique_id, f"{record.name} coverage {record.status}", record.severity, score, rationale, remediation))
    return sorted(findings, key=lambda f: (-f.score, f.technique_id))


def metrics(records: list[TechniqueCoverage], findings: list[CoverageFinding]) -> dict[str, object]:
    statuses = Counter(r.status for r in records)
    tactics = Counter(r.tactic for r in records)
    covered = statuses.get("covered", 0)
    applicable = len(records) - statuses.get("not_applicable", 0)
    coverage_pct = round((covered / applicable * 100), 1) if applicable else 100.0
    return {
        "techniques": len(records),
        "coverage_pct": coverage_pct,
        "status_counts": dict(sorted(statuses.items())),
        "tactic_counts": dict(sorted(tactics.items())),
        "open_findings": len(findings),
        "high_priority_findings": sum(f.score >= 80 for f in findings),
    }
