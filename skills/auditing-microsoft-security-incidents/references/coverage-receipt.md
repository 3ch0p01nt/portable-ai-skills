# Coverage Receipt and Query Ledger

## Contents

- [Purpose](#purpose)
- [Query and API ledger](#query-and-api-ledger)
- [Equivalent-query repeat detection](#equivalent-query-repeat-detection)
- [Coverage receipt](#coverage-receipt)
- [Negative evidence](#negative-evidence)
- [Adapter error mapping](#adapter-error-mapping)
- [Protected references](#protected-references)
- [Sources](#sources)

## Purpose

This reference defines the Task 6 kernel contract for query/API ledger entries
and coverage receipts. It extends the audit output record families without
changing their shared schema. A kernel query entry MUST validate as an
audit-output `queryRecord`. A kernel coverage receipt MUST validate as an
audit-output `coverageReceipt`.

This document is normative for offline and live read workflows. It does not
authorize live calls, mutation, national-cloud endpoints, or direct exposure of
tenant identifiers.

## Query and API ledger

Every adapter envelope that contributes evidence or a gap MUST produce one
ledger entry.

The ledger entry MUST record:

- operation ID, source ID, adapter version, target policy template, and
  authorized purpose;
- `protected-request:` request and query references instead of raw request
  bodies or raw query text;
- requested and effective time window;
- entity, scope, result, runtime, row, byte, pagination, continuation,
  truncation, partial, throttling, retry, status, and error state;
- protected response reference using `protected-evidence:` or
  `not-applicable:none`;
- correlation IDs that are not bearer, token, secret, credential, tenant,
  subscription, workspace, user, or device identifiers; and
- `behavior_bases` using the contract vocabulary.

Raw KQL, OData filters, request bodies, tenant IDs, subscription IDs, workspace
IDs, user IDs, device IDs, continuation tokens, bearer references, and unkeyed
hashes of sensitive values MUST NOT appear in the ledger. Use protected
references instead.

## Equivalent-query repeat detection

The kernel MUST compute a deterministic `equivalent_query_fingerprint` for
repeat detection. The fingerprint input is limited to non-sensitive or
protected-reference fields:

- operation ID;
- source ID;
- `protected-request:` query reference;
- canonical request reference;
- requested time bounds;
- effective time window;
- sorted protected source-scope references;
- protected entity-bound reference; and
- result bounds.

The fingerprint MUST NOT include raw tenant/resource identifiers, raw query
text, raw request bodies, raw continuation tokens, authorization material, or
response payload bytes. Pagination continuation changes alone MUST NOT make the
same query, scope, and time window appear novel.

If the same fingerprint is observed again without a material scope, time,
source, or query-reference change, the router SHOULD treat it as a repeat query
for saturation and budget accounting.

## Coverage receipt

A coverage receipt states what source coverage was actually available for
interpreting evidence and absence. It MUST record:

- source identity and source scope using ordinary-safe text or protected
  references;
- configured and observed state;
- source health, freshness, delay, retention, permission, licensing,
  capability, parser, schema, connector, and transformation state;
- requested time bounds and effective window;
- completeness using the contract vocabulary;
- limitations, gap IDs, error IDs, claim IDs, evidence IDs, and behavior bases;
  and
- retrieval-integrity details for pagination, continuation, truncation, row
  count, and byte count.

Coverage state MUST use the contract vocabulary: `healthy`, `degraded`,
`failed`, `unmonitored`, `structurally_absent`, or `unknown`. Evidence
completeness MUST use the contract vocabulary: `complete`, `partial`,
`insufficient`, `not_assessed`, or `not_applicable`.

## Negative evidence

A negative finding is a statement that something was not observed. A negative
finding MUST NOT be accepted unless the coverage receipt bounds all of these
dimensions:

1. source health;
2. audit enablement;
3. licensing;
4. retention;
5. parser quality; and
6. sensor coverage.

If any dimension is unknown, failed, disabled, unlicensed, outside retention,
unavailable, or not observed, the finding MUST be downgraded to a coverage gap.
Truncated, partial, throttled, denied, malformed, or failed retrieval is also a
coverage gap for absence claims, even when configuration dimensions are
otherwise bounded.
The report MUST say `not found within verified coverage` rather than `did not
occur` unless a stronger detection-probability basis is separately documented.

`not_observed` is not a coverage state. Coverage receipts and helper outputs
MUST use the shared `coverageState` vocabulary and express absence through the
finding disposition or explanatory text.

Missing telemetry is a gap, not benign evidence.

## Adapter error mapping

Adapter error categories map to coverage limitations as follows.

| Adapter condition | Audit error category | Coverage limitation |
|---|---|---|
| Missing permission or authorization boundary | `permission_denied` | `permission_state` |
| Missing license or source capability | `license_unavailable` | `licensing_state` |
| Disabled table or disabled audit source | `coverage_gap` with `table_or_audit_disabled` | `capability_state` and audit enablement |
| Outside retention | `retention_boundary` | `retention_state` |
| Source or workspace not onboarded | `coverage_gap` with `source_not_onboarded` | `connector_health` and sensor coverage |
| Source unavailable or runtime budget exhausted | `source_unavailable` or `budget_exhausted` code | `health_state` |
| Unsupported operation gap | `unsupported_capability` | `capability_state` |

A partial adapter response MAY still contribute evidence, but affected
conclusions MUST carry `partial` completeness or a gap.

Truncated, partial, throttled, denied, malformed, or failed retrieval MUST NOT
emit `complete` evidence completeness. If the source was otherwise healthy, the
coverage receipt MUST degrade coverage to `degraded` and record a retrieval
integrity limitation. If retrieval failed for the source, the receipt MUST use
`failed` coverage state or `insufficient` completeness as applicable.
Adapter envelope status is also retrieval integrity: any status other than
`success` MUST record a limitation and MUST block absence claims.

For paginated adapters, `exhausted` and `not_applicable` are the only terminal
continuation states. `not_observed` means the continuation state is unknown and
MUST NOT support complete coverage.

Any coverage state other than `healthy` MUST record a limitation. Absence claims
MUST NOT be accepted from `degraded`, `failed`, `unmonitored`,
`structurally_absent`, or `unknown` coverage, even if every other boundary is
applicable.

## Protected references

Use only non-bearer opaque protected references in ordinary output:

- `protected-request:` for canonical request, query, and continuation
  references;
- `protected-evidence:` for protected response payloads and raw record
  references;
- `protected-context:` for source, scope, principal, tenant, and resource
  context references; and
- `not-applicable:none` or `unknown:none` when a protected object is not
  applicable or was not observed.

Possession of a protected locator is not access authority. Resolution requires
independent authorization in the protected evidence store.

## Sources

This reference cites source and requirement IDs from the source matrix. Directly
frozen platform behavior includes `R-001`, `R-005`, `R-006`, `R-007`, `R-009`,
`R-011`, `R-012`, `R-037`, `R-039`, and `R-062`. The coverage and
negative-evidence method follows accepted but non-freeze-eligible kernel
requirements `R-010`, `R-014`, `R-015`, `R-017`, `R-018`, `R-019`, `R-022`,
`R-031`, `R-032`, and `R-083` and MUST be labeled
`configurable_project_policy` unless an operation-specific conditional
capability applies.
