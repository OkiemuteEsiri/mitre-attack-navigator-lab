from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .models import TechniqueCoverage

REQUIRED = {
    "technique_id", "name", "tactic", "status", "severity",
    "data_sources", "detections", "owner", "validation_evidence"
}


def load_coverage(path: str | Path) -> list[TechniqueCoverage]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("top-level JSON must be a list")

    records: list[TechniqueCoverage] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"record {index} must be an object")
        missing = REQUIRED - set(item)
        if missing:
            raise ValueError(f"record {index} missing fields: {sorted(missing)}")
        technique_id = str(item["technique_id"])
        if technique_id in seen:
            raise ValueError(f"duplicate technique id: {technique_id}")
        seen.add(technique_id)
        records.append(
            TechniqueCoverage(
                technique_id=technique_id,
                name=str(item["name"]),
                tactic=str(item["tactic"]),
                status=str(item["status"]),
                severity=str(item["severity"]),
                data_sources=frozenset(str(v) for v in item["data_sources"]),
                detections=frozenset(str(v) for v in item["detections"]),
                owner=str(item["owner"]),
                validation_evidence=str(item["validation_evidence"]),
                notes=str(item.get("notes", "")),
            )
        )
    return records
