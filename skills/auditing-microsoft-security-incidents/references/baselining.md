# Baselining and Peer Comparison

## Contents

- [Purpose](#purpose)
- [Baseline records](#baseline-records)
- [Confidence rules](#confidence-rules)
- [Peer comparison rules](#peer-comparison-rules)
- [KQL patterns](#kql-patterns)
- [Requirement trace](#requirement-trace)

## Purpose

Baselines are evidence-quality tools for incident auditing in commercial
Microsoft Defender XDR and Sentinel environments. A baseline MUST be treated as
project methodology, not a universal product guarantee. A baseline comparison
MUST NOT mutate tenant security state and MUST NOT use national-cloud endpoints
in this commercial profile.

## Baseline records

A baseline definition MUST record:

- entity or entity class being compared;
- peer group definition, membership basis, included members, and exclusions;
- metric name, unit, and aggregation;
- inclusive start and exclusive end of the baseline window;
- sample size;
- source identifier;
- coverage expectation, observed coverage, missing days, and telemetry gaps;
- query or evidence ledger item identifiers supporting the calculation; and
- behavior basis, normally `configurable_project_policy`.

Peer group membership MUST be reproducible from cited evidence. Display names,
hostnames, shared addresses, and other weak identifiers SHOULD NOT define peer
membership without stronger supporting identifiers or a recorded limitation.

## Confidence rules

Baseline confidence is separate from source confidence and analytic likelihood.
A baseline confidence record MUST state the configured minimum sample size and
coverage policy used by the kernel or include a reference to the policy version
that supplies those thresholds.

A baseline window that overlaps the possible attacker dwell interval, from the
earliest suspected compromise time through detection time, MUST be flagged as
`potentially_poisoned`. Its confidence MUST be capped and the cap rationale MUST
be recorded. The cap is a project policy because R-029 and R-030 are not frozen
source-eligible requirements.

If sample size is below the configured minimum, confidence MUST be `low`. If
coverage is below the configured minimum, confidence MUST be `low`. Missing days,
connector outages, sensor gaps, parser gaps, retention gaps, or unavailable
telemetry MUST reduce confidence and MUST be represented as gaps, never as
normal behavior or benign evidence.

## Peer comparison rules

A peer comparison result MUST cite query or evidence ledger item identifiers.
Uncited comparisons MUST be rejected or marked unusable.

First-seen and rare behavior is a lead, never a verdict. A rare peer comparison
MAY raise investigation priority, but it MUST NOT establish maliciousness,
benignness, human intent, accountability, campaign membership, or root cause
without corroborating evidence.

## KQL patterns

These examples are illustrative patterns for bounded, read-only baselining. They
use synthetic names and no tenant identifiers. Adapt table and field names only
inside an authorized adapter with source, time, projection, row, and cost bounds.

### Sentinel Log Analytics bounded user activity baseline

```kusto
let baselineStart = datetime(2026-09-01T00:00:00Z);
let baselineEnd = datetime(2026-09-15T00:00:00Z);
let peerUsers = dynamic(["user-a@example.com", "user-b@example.com"]);
SigninLogs
| where TimeGenerated >= baselineStart and TimeGenerated < baselineEnd
| where UserPrincipalName in~ (peerUsers)
| project TimeGenerated, UserPrincipalName, AppDisplayName, ResultType
| summarize sign_in_count=count(), failed_count=countif(ResultType != 0)
    by UserPrincipalName, bin(TimeGenerated, 1d)
| summarize baseline_days=count(), p50_signins=percentile(sign_in_count, 50),
    p95_signins=percentile(sign_in_count, 95) by UserPrincipalName
```

### Defender Advanced Hunting bounded device peer summary

```kusto
let baselineStart = datetime(2026-09-01T00:00:00Z);
let baselineEnd = datetime(2026-09-15T00:00:00Z);
let peerDevices = dynamic(["device-a", "device-b"]);
DeviceProcessEvents
| where Timestamp >= baselineStart and Timestamp < baselineEnd
| where DeviceName in~ (peerDevices)
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName
| summarize process_count=count(), distinct_processes=dcount(FileName)
    by DeviceName, bin(Timestamp, 1d)
| summarize observed_days=count(), p95_process_count=percentile(process_count, 95)
    by DeviceName
```

### Coverage and gap pattern

```kusto
let expectedStart = datetime(2026-09-01T00:00:00Z);
let expectedEnd = datetime(2026-09-15T00:00:00Z);
let expectedDays = range day from expectedStart to expectedEnd - 1d step 1d;
let observedDays = SigninLogs
| where TimeGenerated >= expectedStart and TimeGenerated < expectedEnd
| summarize by day=startofday(TimeGenerated);
expectedDays
| join kind=leftanti observedDays on day
| project missing_day=day
```

These patterns are time-bounded, projected, and summarized. They are not copy
and paste mutation commands, and they do not authorize live access by themselves.

## Requirement trace

This reference supports the Task 6 baseline kernel. It is project methodology
traced to R-029, R-030, R-015, R-017, R-019, R-025, and R-083. R-029 and R-030
remain ineligible for frozen external guarantee status, so generated records
MUST use `configurable_project_policy` unless a future reviewed source updates
the requirement matrix.
