from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet

ALLOWED_STATUSES = frozenset({"covered", "partial", "gap", "not_applicable"})
ALLOWED_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


@dataclass(frozen=True)
class TechniqueCoverage:
    technique_id: str
    name: str
    tactic: str
    status: str
    severity: str
    data_sources: FrozenSet[str]
    detections: FrozenSet[str]
    owner: str
    validation_evidence: str
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.technique_id.startswith("T") or not self.technique_id[1:].replace(".", "").isdigit():
            raise ValueError(f"invalid ATT&CK technique id: {self.technique_id}")
        if self.status not in ALLOWED_STATUSES:
            raise ValueError(f"unsupported status: {self.status}")
        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"unsupported severity: {self.severity}")
        for field_name in ("name", "tactic", "owner"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} is required")


@dataclass(frozen=True)
class CoverageFinding:
    finding_id: str
    technique_id: str
    title: str
    severity: str
    score: int
    rationale: str
    remediation: str

    def __post_init__(self) -> None:
        if not 0 <= self.score <= 100:
            raise ValueError("score must be between 0 and 100")
        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"unsupported severity: {self.severity}")
