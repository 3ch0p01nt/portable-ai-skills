# Analyst Decision Reconstruction

Analyst decision reconstruction is the normative Task 6 decision snapshot method
for SOC handling review. It supports Task 11 by preserving what a reasonable
analyst could know at each material decision time. It implements R-033, R-034,
and R-035 as configurable project policy, not as an external disciplinary
standard.

## Decision snapshot boundary

A decision snapshot MUST record the decision timestamp, decision type, actor
type, alert payload version available, queue state, automation results available,
notes or comments present, playbook version, and telemetry available at the
moment of decision.

Decision types are: `assign`, `severity_change`, `classify`, `escalate`,
`contain_request`, `close`, and `reopen`.

The snapshot MUST use availability time for inclusion. Availability time means
ingestion time, first-visible time, retrieval time, or provided-evidence receipt
time. Source event time alone MUST NOT make evidence available.

Evidence with availability time after the decision timestamp MUST be excluded
from the available snapshot and recorded as later evidence. Later evidence MAY
inform outcome review, but MUST NOT be used to claim the analyst knew or should
have known it.

## Reasonable-analyst test

The assessment MUST use only available evidence, documented policy or playbook
expectations, and the operational context visible at the time. Supported labels
are the existing SOC assessment labels in the contract vocabulary:
`reasonable_with_available_evidence`,
`questionable_with_available_evidence`, `not_assessable`, and
`outcome_only_hindsight`.

An analyst MUST NOT be penalized for unknowable information. A finding that
cites only post-decision evidence is outcome-only hindsight and invalid for the
decision-time assessment.

## Process defect and individual fault

Process and systemic defects MUST be recorded separately from individual fault.
Process defect categories are telemetry, playbook, training, workload, tooling,
handoff, automation, queue, and staffing.

Individual fault requires both:

1. evidence that the material information was available at decision time; and
2. evidence that the required action was documented at decision time.

Absent either element, the record MUST preserve the concern as not supported for
individual fault and route applicable issues to process/systemic defects.

## Metrics and bias controls

Timeliness metrics MUST be paired with quality indicators such as closure
quality, reopen or recurrence indicators, incomplete required tasks, or
later-confirmed error evidence. Speed alone MUST NOT be scored as handling
quality.

Cognitive-bias flags require cited evidence. Supported flags are anchoring,
premature closure, automation bias, alert fatigue, and handoff loss. A label
without cited evidence MUST be rejected.

## Compatibility

The kernel schema `references\kernel\decision-snapshot.schema.json` is closed
and includes the required core fields of the `decisionRecord` definition in
[audit-output.schema.json](audit-output.schema.json). Additional Task 11 fields
remain local to the decision snapshot until the shared audit-output schema is
extended by the integrator.
