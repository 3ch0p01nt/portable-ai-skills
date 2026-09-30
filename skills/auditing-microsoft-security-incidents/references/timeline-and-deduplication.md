# Timeline and Deduplication Kernel

## Purpose

This reference defines the timeline and deduplication rules for the commercial
Microsoft security incident auditor. It extends the multi-clock timeline output
required by [operating-contract.md](operating-contract.md),
[report-contract.md](report-contract.md), and
[audit-output.schema.json](audit-output.schema.json).

## Normative rules

- Timeline records MUST distinguish source event time, ingestion or receipt
  time, update time when present, and retrieval time. Requirement R-022.
- Event time MUST be normalized to UTC for comparison while preserving the raw
  timestamp string and source timezone or locale beside the normalized value.
  Requirements R-022 and R-042.
- When a timestamp carries an explicit offset but no source timezone was
  supplied, timestamp provenance MUST record `source_timezone: explicit_offset`
  rather than an empty string.
- Ingestion time, `_TimeReceived`, `ingestion_time()`, or retrieval time MUST
  NOT be substituted for missing event time. A missing event time is a gap.
  Records without event time MUST be returned in an unplaced set and MUST NOT
  participate in ordered event sequences. Requirement R-022.
- Offset-free localized timestamps MUST be parsed with invariant culture and the
  recorded source timezone. Ambiguous daylight-saving timestamps MUST produce an
  uncertainty interval rather than a single false instant. Requirement R-023.
- Offset-free timestamps without a declared source timezone MUST NOT default to
  UTC. Whitespace-only source timezones are not declared. They are unplaced
  event times, MUST emit a gap, and MUST record `source_timezone: not_provided`.
- ISO-8601 leap seconds are not normalized. They MUST be rejected or represented
  as a parsing gap because the kernel is leap-free.
- Clock-offset correction MUST retain the raw source value, the uncorrected UTC
  source event time, the correction method, offset, and evidence IDs. Requirement
  R-023. Clock-offset correction MUST use an injected audit time and MUST NOT
  call the system clock. Ambiguous local timestamp corrections MUST preserve a
  widened uncertainty interval and MUST NOT raise timestamp confidence.
- Ordering MUST use uncertainty intervals. If two intervals overlap, the order is
  indeterminate and MUST NOT be rendered as a sequence.
- Ordering MUST also be indeterminate when either record lacks event time.
- Late-arriving data MUST be flagged from event-to-ingestion latency. Latency is
  coverage and freshness evidence, not a reason to rewrite event time.
- Deduplication MUST use upstream lineage. Same source and same upstream record
  are duplicate copies only under ordinal, case-sensitive identifier comparison;
  similar-looking records from different upstream records or differently cased
  identifiers remain distinct events. Requirement R-016.
- Empty upstream record identifiers MUST be rejected before lineage grouping.
- Duplicates MUST NOT be counted as independent corroboration, but retained
  duplicate IDs SHOULD remain available for provenance and stop receipts.
- All behavior bases for these deterministic methods are
  `configurable_project_policy` unless a specific platform source supplies a
  narrower `guaranteed_behavior`.

## Record contract

The kernel record at `references\kernel\timeline.schema.json` is a closed JSON
Schema draft 2020-12 object. It contains the audit-output `timelineRecord`
projection fields:

- `timeline_id`
- `event_ref`
- `time_kind`
- `time_value`
- `uncertainty`
- `claim_ids`
- `evidence_ids`
- `gap_ids`
- `error_ids`
- `behavior_bases`

It also records timestamp provenance, confidence, uncertainty interval, latency,
deduplication lineage, and optional clock-offset correction.

## Deterministic functions

`Timeline.Kernel.psm1` exposes pure functions only:

- `New-HavocTimelineRecord` normalizes timestamps, records gaps, uncertainty,
  latency, lineage, and audit-compatible projection fields.
- `Add-HavocClockOffsetCorrection` applies a documented clock offset while
  preserving the raw and uncorrected source event time. Callers MUST pass
  `-AsOf` as an RFC 3339 timestamp with an explicit offset.
- `Compare-HavocTimelineOrder` returns `order_indeterminate` when uncertainty
  intervals overlap.
- `Merge-HavocTimelineRecords` removes duplicate upstream copies without
  collapsing distinct lookalike events, using case-sensitive lineage grouping.
- `Resolve-HavocTimelinePlacement` returns `placed_records` for ordered timeline
  use and `unplaced_records` for records that lack event time.
- `Select-HavocTimelineAuditProjection` emits the existing audit-output
  timeline projection.
- `Get-HavocAuditTimelineProjectionSchema` supports compatibility testing
  against the existing audit-output timeline shape.

## Output language

Reports MUST say `not found within verified coverage` when a timeline source is
empty, delayed, truncated, or outside retention. Reports MUST NOT infer causality
from sequence alone, and MUST keep uncertain ordering uncertain.
