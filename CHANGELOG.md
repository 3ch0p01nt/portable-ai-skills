# Changelog

## 1.2.0 - 2026-09-04

### Added

- Published `identity-threat-investigator` for evidence-grounded investigation of identity compromise, baseline deviations, MFA abuse, token or session reuse, workload identities, and post-authentication persistence.
- Added Microsoft cloud telemetry coverage with MDI, MDE, and Advanced Hunting as sensor-fed hybrid context without assuming direct host artifacts.
- Added a typed investigation schema, eight redaction rules, 12 known-answer evaluations, 14 authoritative source records, and deterministic PowerShell validation and security scanning.

### Safety and scope

- The skill is read-only and produces approval-ready response options rather than changing identities, sessions, credentials, devices, applications, consent, Conditional Access, or tenant configuration.
- Empty query results cannot establish safety until table availability, schema, ingestion, licensing, and retention are validated.
- MFA success, anomaly detections, location, and risk scores remain evidence inputs rather than automatic compromise or clearance verdicts.

## 1.1.0 - 2026-08-28

### Added

- Published `cisco-device-compromise-investigation` skill v2.3.0 baseline for authorized network-device incident response.
- Added preview-first local folder analysis, evidence/redaction schemas, platform and threat routing, detection templates, 72 evaluations (41 P0), and 45 source records.
- Added cross-platform Python 3.11+ offline validation/tests and a separate strict online source-freshness checker.
- Added Windows and Ubuntu offline CI plus weekly source verification.

### Safety and sources

- Live-device commands remain human-executed only; the skill never connects to a device.
- Untrusted artifacts are inert evidence, secrets are redacted, destructive collection is routed through current platform guidance, and conclusions retain untested/untrusted layers.
- Hardened SNMPv3 secret redaction, export/Office classification, archive budgets, unresolved device identity, zero-count suppression detections, and fallback source-version checks.
- Sources were verified on 2026-08-28. The Sygnia source permits documented manual web verification for 30 days and must be reverified monthly while automated retrieval remains blocked.
