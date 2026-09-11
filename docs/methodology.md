# Coverage Assessment Methodology

## 1. Define the defensive objective

Select ATT&CK techniques because they represent relevant threat behaviors for the synthetic scenario, not because a broad technique count looks impressive. Each technique needs an accountable owner and an explicit defensive purpose.

## 2. Map telemetry

For each technique, document the minimum data sources needed to observe the behavior. A data source is considered useful only when fields required for triage are retained with sufficient context and timestamp quality.

## 3. Map detection analytics

Coverage requires at least one documented analytic or correlation approach. Merely collecting telemetry does not constitute detection coverage.

## 4. Validate safely

Validation uses synthetic fixtures and benign event metadata. This repository does not disable controls, execute malicious payloads, harvest credentials, exploit systems, or target production assets. Evidence should show that the expected fields reach the analytic and that the result is reproducible.

## 5. Classify coverage

- **covered** — telemetry, analytic, owner, and repeatable validation evidence are present.
- **partial** — meaningful control coverage exists but tuning, telemetry, scope, or validation remains incomplete.
- **gap** — material detection coverage is missing or cannot be demonstrated.
- **not_applicable** — technique is explicitly excluded from the assessed scenario with documented rationale.

## 6. Prioritize gaps

The engine combines business-defined severity with the coverage state. Missing telemetry, detection mappings, and validation evidence increase the score. Scoring is a transparent prioritization aid, not an assertion of compromise or exploitability.

## 7. Remediate

A remediation should identify the required data source, detection owner, analytic change, validation procedure, and expected evidence. Closure based only on a ticket state is insufficient.

## 8. Revalidate

After remediation, rerun the same synthetic validation fixture and capture evidence that the detection behaves as expected. Update the technique status only after that evidence exists.

## ATT&CK context in the sample

The synthetic dataset includes T1078, T1110.003, T1059.001, T1021.001, T1562.001, and T1190. These mappings are threat-model references. They do not indicate that those behaviors occurred in a real environment.
