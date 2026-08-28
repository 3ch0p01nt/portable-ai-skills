# Changelog

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
