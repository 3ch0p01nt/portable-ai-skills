# KQL and Response Guidance

## Query contract

Every generated query must state:

- investigative question;
- schema and table names;
- required connector and license;
- event-time and ingestion-time fields;
- time range;
- typed tuning parameters;
- projected evidence columns;
- expected false positives;
- expected result meaning;
- validation status.

Prefer ASIM only when its parser and source coverage are verified. Otherwise use documented native tables. Do not interpolate untrusted values into query text without escaping or typed parameters.

## Required preflight

Before interpreting a query:

1. Verify each table exists and has recent events.
2. Verify expected fields exist and are populated.
3. Check first and last event time against the incident window.
4. Check ingestion delay, retention, sampling, and connector filters.
5. Confirm the query uses the intended event-time field.
6. Mark the query `validated: false` until it has run successfully in the target environment.

## Query families

- all activity for an identity across interactive and non-interactive sources;
- authentication-method or device change followed by access;
- Conditional Access outcome compared with expected coverage;
- token or session identifiers linked to downstream operations;
- new application, consent, credential, owner, or privilege followed by use;
- human baseline deviation;
- workload-identity source, schedule, target, and operation deviation;
- mailbox forwarding, file access, sharing, and Graph-operation sequences;
- MDI identity detections correlated with MDE device and Entra evidence.

Output columns should support evidence, not conclusions. Prefer names such as `ObservedSequence` or `PotentialReplayContext`, not `ConfirmedAttack`.

## Response option contract

The skill proposes but does not execute response.

Each option includes:

- evidence threshold and rationale;
- affected identities and resources;
- required role and approver;
- reversible, high-impact, or destructive classification;
- evidence-preservation prerequisite;
- business and forensic impact;
- expected session or token coverage;
- rollback or recovery path;
- monitoring required after action.

Always escalate:

- privileged or emergency-access identities;
- federation or synchronization infrastructure;
- Conditional Access changes;
- authentication-method removal;
- application or consent changes;
- device wipe or object deletion;
- multi-identity or tenant-wide action;
- any action based on unvalidated queries or incomplete coverage.
