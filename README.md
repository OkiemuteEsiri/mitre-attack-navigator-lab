# MITRE ATT&CK Coverage Engineering Lab

A defensive Detection Engineering project for measuring, prioritizing, and validating ATT&CK-aligned telemetry and analytic coverage using synthetic data only.

## Problem statement

ATT&CK matrices are often used as static checklists. That can create false confidence: a technique may be marked "covered" because a log source exists even when no usable analytic, owner, or validation evidence exists. This project treats ATT&CK coverage as an engineering control with explicit evidence requirements.

## What this project demonstrates

- ATT&CK-aligned detection coverage modeling
- fail-closed ingestion and schema validation
- deterministic 0–100 coverage-gap prioritization
- telemetry, analytic, ownership, and evidence mapping
- safe remediation and revalidation workflows
- executive and technical reporting
- unit-testable security engineering logic
- least-privilege CI/CD validation

## Architecture

```text
Synthetic ATT&CK coverage JSON
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
 prioritized       metrics
 findings             |
       \              /
        v            v
         Markdown report
```

See [`docs/architecture.md`](docs/architecture.md) for component and trust-boundary details.

## Coverage model

Each technique records:

- ATT&CK technique ID and name
- tactic
- defensive severity
- coverage state (`covered`, `partial`, `gap`, `not_applicable`)
- required data sources
- mapped detections
- accountable owner
- validation evidence
- optional engineering notes

A mapping is not treated as fully covered without repeatable validation evidence.

## Risk prioritization

The engine starts from severity and adjusts for coverage state. Missing telemetry, detection mappings, or validation evidence increases the score. Scores are bounded from **0–100** and are intended for remediation ordering, not for asserting compromise or predicting exploitability.

Findings are deterministic: stable SHA-256-derived IDs are generated from the technique, finding type, and owner so repeat assessments are traceable.

## Synthetic ATT&CK mappings

The included dataset models defensive coverage for:

| Technique | Description | Defensive purpose |
|---|---|---|
| T1078 | Valid Accounts | identity anomaly detection |
| T1110.003 | Password Spraying | distributed authentication-failure detection |
| T1059.001 | PowerShell | endpoint/process telemetry validation |
| T1021.001 | Remote Desktop Protocol | east-west remote-service detection |
| T1562.001 | Impair Defenses | security-control health monitoring |
| T1190 | Exploit Public-Facing Application | application/WAF telemetry coverage |

These are threat-model mappings only. They do **not** claim that any adversary activity occurred.

## Repository structure

```text
.github/workflows/ci.yml      least-privilege CI validation
data/synthetic_coverage.json realistic fictional coverage records
docs/architecture.md         technical design and trust boundaries
docs/methodology.md          assessment/remediation methodology
reports/example-assessment.md example recruiter-facing assessment
src/models.py                immutable validated domain models
src/loader.py                fail-closed JSON ingestion
src/coverage_engine.py       scoring, findings, and metrics
src/report.py                Markdown reporting
src/cli.py                   offline command-line interface
tests/test_coverage.py       unit tests
```

## Usage

Requires Python 3.11+ and no third-party dependencies.

```bash
python -m src.cli data/synthetic_coverage.json
```

Generate a report:

```bash
python -m src.cli data/synthetic_coverage.json --report coverage-report.md
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Methodology

1. Define the relevant defensive objective.
2. Map the telemetry required to observe the technique.
3. Map one or more detection analytics.
4. Validate using synthetic fixtures and benign event metadata.
5. Classify coverage as covered, partial, gap, or not applicable.
6. Prioritize material gaps using transparent scoring.
7. Remediate telemetry, analytic, ownership, or validation deficiencies.
8. Re-run the same validation and capture evidence before closure.

Full methodology: [`docs/methodology.md`](docs/methodology.md).

## Remediation and validation workflow

A coverage-gap ticket is not considered resolved simply because configuration changed. Closure should show:

- required telemetry is present and usable;
- the intended analytic is mapped and owned;
- expected triage fields are preserved;
- synthetic validation produces repeatable evidence;
- the technique status is reassessed after the change.

## CI/CD security checks

The GitHub Actions workflow uses `contents: read` only and is configured to:

- compile source and tests;
- run unit-test discovery;
- validate the synthetic coverage dataset;
- render a Markdown assessment.

A workflow file being present does not imply a successful run; check the repository's Actions/status view for actual execution results.

## Safety and limitations

This repository is intentionally defensive and offline. It does not:

- execute ATT&CK techniques;
- contain exploit payloads, credential theft, malware, persistence, C2, or defense-impairment code;
- disable endpoint controls;
- target production systems;
- perform live scanning or enumeration;
- contain employer/client data, real credentials, or confidential detections.

The dataset is synthetic and simplified. Production adoption would require data provenance, schema versioning, secure ingestion, environment-specific control ownership, change governance, and detection-quality metrics such as false-positive rate and mean time to triage.

## Skills demonstrated

- Detection Engineering
- MITRE ATT&CK mapping
- security control validation
- Python defensive tooling
- risk prioritization
- telemetry architecture
- remediation governance
- evidence-based reporting
- unit testing
- secure CI/CD design

## Roadmap

- export ATT&CK Navigator-compatible layer JSON;
- add tactic-level heat-map generation;
- model control-to-technique many-to-many relationships;
- add validation freshness and evidence-expiry logic;
- introduce detection-quality metrics and tuning history;
- support versioned ATT&CK datasets without requiring live network access.

## License / use

Portfolio and educational defensive-security project. All examples are fictional and synthetic.
