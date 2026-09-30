# Hypothesis and causal analysis kernel

## Contents

- [Purpose](#purpose)
- [Competing hypotheses](#competing-hypotheses)
- [Diagnostic evidence matrix](#diagnostic-evidence-matrix)
- [Causal graph](#causal-graph)
- [Root-cause factors](#root-cause-factors)
- [Attribution boundaries](#attribution-boundaries)
- [Audit-output compatibility](#audit-output-compatibility)
- [Sources and requirement IDs](#sources-and-requirement-ids)

## Purpose

This reference defines the Task 6 hypothesis and causal-analysis kernel for the
commercial Microsoft incident auditor. It extends the operating contract without
changing the canonical output families in [operating-contract.md](operating-contract.md),
[report-contract.md](report-contract.md), [contract-vocabulary.json](contract-vocabulary.json),
and [audit-output.schema.json](audit-output.schema.json).

The rules are `configurable_project_policy` unless a specific record states a
narrower `conditional_capability` or `explicit_gap` basis. Hypothesis and causal
records MUST preserve likelihood separately from analytic confidence.

## Competing hypotheses

An audit MUST consider at least one malicious and one benign or expected
hypothesis unless a class is explicitly ruled out with cited evidence. The
standard hypothesis families are:

- `malicious`
- `benign_expected`
- `detection_defect`
- `data_defect`
- `systemic`

A ruled-out hypothesis MUST keep its statement, rule-out evidence, and remaining
information gaps. Null, empty, or whitespace citation arrays are zero citations
and MUST NOT rule out a hypothesis. Missing telemetry is a gap, not benign
evidence.

## Diagnostic evidence matrix

Each matrix row records one evidence item against each active hypothesis using
an ACH-style consistency rating: `consistent`, `contradicts`, `neutral`, or
`not_applicable`.

Evidence that is consistent with all active hypotheses MUST be assigned low
diagnosticity. Low-diagnosticity common evidence MUST NOT drive hypothesis
ranking. Ranking evidence SHOULD come from cited evidence that separates at
least two plausible hypotheses or directly contradicts a leading alternative.

Repeated records from the same upstream lineage MAY corroborate that a source
reported consistently, but they MUST NOT be counted as independent
corroboration.

## Causal graph

A causal graph contains causal nodes and causal edges. Edge type is a closed enum:

- `association`
- `mechanism-supported`
- `intervention-supported`
- `counterfactual`

Every edge MUST preserve `cause_time`, `effect_time`, and uncertainty. Timestamp
values MUST be RFC 3339 with an explicit offset and MUST be normalized through
the shared UTC timestamp primitive. A causal edge is established only when the
cause latest possible time is at or before the effect earliest possible time.
Overlapping windows yield `precedence_uncertain` and MUST NOT support an
established causal claim. Temporal order alone is insufficient for causality.

A `mechanism-supported` edge MUST cite mechanism evidence. Null, empty, or
whitespace citation arrays are zero citations. Any edge stronger than
`association` MUST cite independent corroboration from a different upstream
lineage. Similarity, recurrence, reputation, ATT&CK mapping, or sequence alone
MUST NOT be promoted to causal proof.

The graph MUST be acyclic.

## Root-cause factors

Root cause is multi-factor. A complete analysis MUST account for every role
below as either a present factor or an explicit gap:

- `proximate_event`
- `entry_vector`
- `enabling_technical_condition`
- `failed_control`
- `organizational_process_cause`
- `latent_systemic_condition`

An `association` edge alone MUST NOT be named root cause. Root-cause statements
SHOULD describe contributing factors and unresolved alternatives instead of a
single unsupported label.

## Attribution boundaries

Technical identification, human attribution, intent, and accountability are
separate fields. Technical logs may identify an account, device, session,
application, token, process, or action. Technical logs alone MUST NOT set human
attribution, intent, or accountability above low confidence.

Human attribution and intent require independent corroboration and authorized
human review. Business, legal, HR, disciplinary, or accountability decisions are
outside autonomous auditor authority.

## Audit-output compatibility

Hypothesis records project to `hypothesisRecord` by preserving:
`hypothesis_id`, `statement`, `likelihood`, `analytic_confidence`, supporting
and contradicting evidence IDs, information needed, claim IDs, gap IDs, error
IDs, and behavior bases.

Causal edges project to `causalRecord` by preserving: `causal_id`, `from_ref`,
`to_ref`, `relationship_basis`, `statement`, claim IDs, evidence IDs, gap IDs,
error IDs, and behavior bases. The kernel keeps `edge_type` as an additional
field because current output vocabulary uses `relationship_basis` values.
`mechanism-supported` maps to `supported_mechanism`; association maps to
`association`. `intervention-supported` and `counterfactual` remain kernel edge
types and require an integrator vocabulary update before they can be represented
as first-class `relationship_basis` values.

## Sources and requirement IDs

This kernel implements project methodology from R-024 through R-028 and uses
R-013 through R-017, R-022, R-025, R-027, R-028, R-031, and R-039 as related
constraints. The primary NIST and CISA root-cause claims support root-cause and
enabling-condition analysis; the graph model and ACH matrix remain
non-freeze-eligible project methodology. See source IDs NIST-IR,
CISA-PLAYBOOK, ACH, W3C-PROV, NIST-FORENSICS, NIST-LOG, FIRST-ETHICS, and
NIST-PRIVACY in the source register.
