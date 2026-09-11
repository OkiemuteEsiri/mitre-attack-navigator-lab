# Example ATT&CK Coverage Assessment

## Executive Summary

Synthetic assessment scope: six ATT&CK techniques spanning identity, execution, lateral movement, defense evasion, and initial access.

- **Fully covered:** T1078 Valid Accounts, T1059.001 PowerShell
- **Partial coverage:** T1110.003 Password Spraying, T1021.001 RDP, T1190 Exploit Public-Facing Application
- **Coverage gap:** T1562.001 Impair Defenses

## Highest-priority gap

**T1562.001 — Impair Defenses** is modeled as a critical coverage gap because the sample has control-health telemetry but no mapped detection analytic or validation evidence. The remediation path is to define a safe control-state analytic using synthetic configuration fixtures, document ownership, and capture repeatable evidence. No endpoint protection is disabled as part of validation.

## Validation principle

A technique is not marked covered merely because a log source exists. Full coverage requires usable telemetry, a mapped analytic, accountable ownership, and repeatable validation evidence.

## Safety boundary

All records are fictional and synthetic. This example does not represent a real environment, breach, customer, employer, or production system.
