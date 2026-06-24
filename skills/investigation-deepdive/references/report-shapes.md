# Report Shapes

## Initial Investigation Plan

```text
Seed summary:
Extracted entities:
Assumptions and missing context:
Time windows:
Initial hypotheses:
Pivot plan:
Evidence to collect:
```

## Query or Pivot Packet

```text
Purpose:
Data source:
Time range:
Query or pivot:
Expected result shape:
How to interpret results:
Execution status:
```

Use `Execution status: not executed` when live execution was not authorized or not available.

## Final Investigation Report

Use this shape for final reports:

```text
1. Executive Summary
   - One-paragraph explanation of what happened.
   - Verdict.
   - Severity.
   - Confidence.

2. Seed Event Summary
   - Original event.
   - Why it was investigated.
   - Key entities extracted.

3. Investigation Timeline
   - Chronological sequence of important activity.
   - Timestamps, entities, and evidence references.

4. Key Findings
   - Finding.
   - Evidence.
   - Confidence.
   - MITRE ATT&CK mapping where applicable.

5. Root Cause Assessment
   - Most likely root cause.
   - Supporting evidence.
   - Gaps or uncertainty.

6. Scope / Blast Radius
   - Affected users.
   - Affected hosts.
   - Affected resources.
   - Related indicators.
   - Scope classification.

7. Suspicious Activity Discovered
   - Additional suspicious events found during pivoting.
   - Why they matter.
   - Linkage to the seed event.

8. Dead Ends / Ruled-Out Leads
   - Threads investigated that did not produce meaningful evidence.
   - Why they were closed.

9. Recommended Analyst Actions
   - Immediate read-only follow-up.
   - Containment recommendations requiring approval.
   - Remediation recommendations.
   - Detection improvements.
   - User, host, and owner follow-up.

10. Queries Run
   - Query purpose.
   - Query text.
   - Data source.
   - Time range.
   - Result summary.
   - Execution status; use `Execution status: not executed` when live execution was not authorized or not available.

11. Evidence Ledger
   - Finding ID.
   - Entity.
   - Claim.
   - Evidence.
   - Source.
   - Timestamp.
   - Confidence.
   - MITRE ATT&CK mapping.

12. Open Questions
   - What remains unknown.
   - What telemetry would resolve it.
```

## Analyst Actions

Separate actions into:

- Recommended immediate read-only validation.
- Actions requiring explicit approval.
- Actions that may affect business operations.
- Longer-term remediation.
- Detection and logging improvements.
