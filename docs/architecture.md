# Technical Architecture

## Purpose

This project models MITRE ATT&CK as a defensive coverage-management problem rather than an offensive technique catalog. It answers four operational questions: which techniques matter to the scenario, which telemetry sources exist, which detection analytics are mapped, and whether repeatable validation evidence demonstrates that coverage works.

## Data flow

```text
Synthetic coverage JSON
        |
        v
 fail-closed loader
        |
        v
 immutable domain models
        |
        v
 coverage assessment engine
   |              |
   v              v
findings       metrics
   \              /
    v            v
     Markdown report
```

## Components

### `src/models.py`
Defines immutable `TechniqueCoverage` and `CoverageFinding` models. Validation rejects malformed ATT&CK identifiers, unsupported coverage states, invalid severity values, and missing ownership.

### `src/loader.py`
Loads local JSON only. It rejects non-list payloads, malformed records, missing required fields, and duplicate technique IDs. This fail-closed behavior prevents silent corruption of portfolio metrics.

### `src/coverage_engine.py`
Transforms partial or missing technique coverage into prioritized findings. Scoring is deterministic and bounded from 0 to 100. Missing telemetry, analytics, or validation evidence adds risk because an unvalidated mapping is not operational coverage.

### `src/report.py`
Produces a recruiter- and analyst-readable Markdown assessment with executive metrics, prioritized findings, remediation guidance, and an interpretation warning.

### `src/cli.py`
Provides an offline interface suitable for local analysis or CI. It performs no network requests and does not execute ATT&CK techniques.

## Trust boundaries

The repository intentionally contains only synthetic data. It does not ingest production SIEM events, credentials, endpoint telemetry, cloud tenant data, or confidential detection content. Any future production integration should add schema versioning, source authentication, data classification, secure secret handling, and auditable provenance.

## Design principles

- Defensive use of ATT&CK mappings.
- Deterministic and explainable scoring.
- Fail-closed input validation.
- Explicit evidence requirements.
- Separation of threat-model context from evidence of compromise.
- No offensive payloads or live technique execution.
