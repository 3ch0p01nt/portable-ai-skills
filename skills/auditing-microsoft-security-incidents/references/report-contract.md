# Microsoft Security Incident Auditor Report Contract

## Contents

- [1. Purpose](#1-purpose)
- [2. Normative dependency](#2-normative-dependency)
- [3. Report forms](#3-report-forms)
- [4. Stable section ordering](#4-stable-section-ordering)
- [5. Section presence rules](#5-section-presence-rules)
- [6. Report metadata](#6-report-metadata)
- [7. Executive assessment](#7-executive-assessment)
- [8. Original incident and auditor comparison](#8-original-incident-and-auditor-comparison)
- [9. Authorization, safety, coverage, and limitations](#9-authorization-safety-coverage-and-limitations)
- [10. Evidence, query, entity, and timeline presentation](#10-evidence-query-entity-and-timeline-presentation)
- [11. Hypotheses and causal analysis](#11-hypotheses-and-causal-analysis)
- [12. SOC decision-time review](#12-soc-decision-time-review)
- [13. Detection, automation, and recurrence review](#13-detection-automation-and-recurrence-review)
- [14. Containment and recovery review](#14-containment-and-recovery-review)
- [15. Privacy, business, and legal facts](#15-privacy-business-and-legal-facts)
- [16. Recommendations](#16-recommendations)
- [17. Independent QA](#17-independent-qa)
- [18. Stop receipt and errors](#18-stop-receipt-and-errors)
- [19. Citations and analytic language](#19-citations-and-analytic-language)
- [20. Machine-readable schema contract](#20-machine-readable-schema-contract)
- [21. Human-readable Markdown contract](#21-human-readable-markdown-contract)
- [22. Prohibited report behavior](#22-prohibited-report-behavior)
- [23. Conformance checklist](#23-conformance-checklist)

## 1. Purpose

This contract defines the stable output ordering, required content, conditional
content, citation rules, and analytic language for Microsoft security incident
audit reports.

The report compares the original incident record and decision with an
independent auditor assessment. It is an evidence-based review, not an
autonomous containment, legal, business, HR, disciplinary, or attribution
decision.

## 2. Normative dependency

The [operating contract](operating-contract.md) is normative for inputs,
safety, autonomy, evidence, errors, stopping, privacy, and versioning. The
[contract vocabulary](contract-vocabulary.json) is normative for current
versions, every closed enum, section IDs and manifests, root collection names,
behavior-basis ordering, and locale labels. The
[audit output schema](audit-output.schema.json) is normative for the JSON
shape. This document explains those artifacts and does not redefine them.

## 3. Report forms

Every audit MUST produce:

1. a machine-readable UTF-8 JSON document; and
2. a human-readable UTF-8 Markdown report.

Both forms MUST describe the same assessment, evidence, limitations, errors,
and stop condition. The Markdown report MAY summarize protected evidence, but
it MUST preserve citations to audit-local evidence IDs and MUST NOT imply that
redaction means evidence was absent.

## 4. Stable section ordering

Section IDs, ordinals, presence, status, evidence completeness, and collection
mappings are normative. Machine-readable reports MUST represent the order
through the `sections` array and MUST NOT rely on JSON object-member order.
Human-readable headings are rendering metadata: renderers MUST resolve each
`section_id` through the requested locale in the versioned label map, falling
back to the declared default locale. A translated-label change alone does not
change this section contract.

The `collection_refs` value is the exact ordered list of canonical root
collections that supply records for the section. Every listed collection MUST
exist even when it is empty. A section MUST NOT add, remove, reorder, or
substitute a collection reference without a major contract-version change.

| Ordinal | `section_id` / label key | Presence | `collection_refs` |
|---:|---|---|---|
| 1 | `report_metadata` | required | `report_metadata` |
| 2 | `executive_assessment` | required | `incident_summary, evidence_records` |
| 3 | `incident_comparison` | required | `incident_summary, decision_records, evidence_records` |
| 4 | `authorization_and_safety` | required | `report_metadata, query_records, coverage_receipts, errors` |
| 5 | `coverage_and_limitations` | required | `coverage_receipts, errors` |
| 6 | `query_and_retrieval` | required | `query_records, coverage_receipts, errors` |
| 7 | `evidence_ledger` | required | `evidence_records` |
| 8 | `entity_resolution` | required | `entity_records, evidence_records` |
| 9 | `timeline` | required | `timeline_records, evidence_records` |
| 10 | `competing_hypotheses` | required | `hypothesis_records, evidence_records` |
| 11 | `causal_analysis` | required | `causal_records, evidence_records` |
| 12 | `soc_decision_review` | required | `decision_records, evidence_records` |
| 13 | `detection_audit` | required | `query_records, coverage_receipts, evidence_records` |
| 14 | `automation_provenance` | conditional | `automation_records, evidence_records` |
| 15 | `recurrence_review` | required | `recurrence_records, evidence_records` |
| 16 | `containment_and_recovery` | conditional | `recovery_records, evidence_records` |
| 17 | `privacy_review` | required | `privacy_records` |
| 18 | `business_and_legal_facts` | conditional | `business_fact_records, legal_fact_records, evidence_records` |
| 19 | `recommendations` | required | `evidence_records` |
| 20 | `independent_qa` | required | `qa_records` |
| 21 | `stop_and_errors` | required | `stop_receipt, errors` |

## 5. Section presence rules

A required section MUST be present and MUST contain both `section_status` and
`evidence_completeness`. Status records whether the section contract was
fulfilled; completeness records the sufficiency of available evidence. A
section MAY be complete while reporting partial evidence.

Every section and every material claim MUST include
`behavior_bases`. Project-defined hypotheses, SOC review, causality,
automation, recurrence, privacy workflow, business/legal routing,
recommendations, and QA MUST use `configurable_project_policy` unless the
specific record is an operation-specific `conditional_capability` or
`explicit_gap`.

Claim- and record-level bases are authoritative. The section array MUST be the
sorted-unique union of those values using the vocabulary artifact's declared
order.

A conditional section MUST still retain its stable key and heading. When its
trigger is absent, it MUST use `section_status: not_applicable` and state the
trigger that was not observed. When evidence is unavailable, it MUST use
`partial` or `blocked`, not `not_applicable`.

No section MAY disappear merely because its data source failed. Source failure
is reportable content.

## 6. Report metadata

`Report Metadata` MUST include:

- report ID and creation time;
- audit-local pseudonymous `audit_incident_ref`;
- non-bearer `protected_incident_link_ref` requiring independent authorization;
- operating mode;
- reference window;
- contract, schema, and policy versions;
- adapter and source versions;
- report handling marking;
- auditor identity or execution identity;
- request-specific `authorization_purpose` and `authorization_scope_ref`;
- `protected_evidence_store_reference_class`, using the closed class declared in
  `contract-vocabulary.json`; and
- report status.

Raw product incident IDs or seeds, credentials, tenant identifiers, protected
raw queries, and sensitive returned records MUST NOT appear.

## 7. Executive assessment

`Executive Assessment` MUST state:

- the leading analytic judgment;
- its qualitative likelihood;
- analytic confidence as a separate value;
- the most important supporting evidence;
- the most important contradicting evidence;
- the original disposition;
- whether the auditor agrees, disagrees, or cannot determine;
- material coverage limits;
- unresolved material frontier; and
- the exact stop cause.

The executive assessment MUST NOT introduce a claim that lacks support in a
later cited section.

## 8. Original incident and auditor comparison

The comparison MUST preserve the original:

- title, severity, status, classification, determination, and closure reason;
- ownership and timestamps;
- analyst notes;
- automation-generated notes;
- linked alerts and entities;
- decision-time evidence; and
- known queue, workload, playbook, or handoff context.

The auditor side MUST separately state:

- observed facts;
- inferred explanation;
- assumptions;
- remaining alternatives;
- agreement or disagreement with each material original field;
- whether disagreement results from later evidence, evidence originally
  available but unused, telemetry defects, detection defects, or policy
  differences; and
- whether reopening or human escalation is recommended.

Later evidence MUST be clearly labeled and MUST NOT be attributed to the
original analyst's decision-time knowledge.

## 9. Authorization, safety, coverage, and limitations

`Authorization and Safety` MUST record:

- authorized purpose;
- approved sources and scope;
- commercial-cloud validation;
- denied requests;
- excess credential privilege observations;
- whether retrieval-job state was considered or used; and
- confirmation that recommendations were not executed.

`Coverage and Limitations` MUST summarize every
[coverage receipt](operating-contract.md#15-coverage-and-telemetry-health),
including source, scope, state, delay, retention, permission, license, parser,
connector, transformation, pagination, truncation, and partial-response status.

Absence language MUST use `not found within verified coverage` unless the report
documents a stronger detection-probability basis.

## 10. Evidence, query, entity, and timeline presentation

`Query and Retrieval Record` MUST list each operation ID, source, authorized
purpose, time and scope bounds, adapter version, response classification,
pagination, truncation, partial results, throttling, and related error IDs.
Sensitive query text MUST be represented only by an approved summary and
protected reference.

`Evidence Ledger` MUST contain, for each material evidence item:

- evidence ID;
- evidence class;
- source and provenance;
- raw reference;
- normalized value;
- transformations;
- source and baseline confidence;
- dependence and upstream lineage;
- clocks;
- limitations;
- handling marking; and
- claims that cite the item.

`Entity Resolution` MUST show stable identifiers, aliases, weak identifiers,
lifecycle intervals, collisions, merge or split rationale, confidence, and the
boundary between technical identity and human attribution.

`Multi-Clock Timeline` MUST distinguish event, ingestion or receipt, update,
retrieval, and normalized comparison time. Uncertain ordering MUST remain
uncertain.

## 11. Hypotheses and causal analysis

`Competing Hypotheses` MUST include, when relevant:

- malicious;
- benign or authorized;
- data, telemetry, parser, connector, or detection defect; and
- systemic or control failure.

Each hypothesis MUST show supporting evidence, contradicting evidence,
information still needed, qualitative likelihood, analytic confidence, source
dependence, and the sensitivity check.

`Multi-Factor Causal Analysis` MUST distinguish:

- observed event;
- inferred proximate mechanism;
- entry or initiating path, if evidenced;
- enabling technical conditions;
- failed or missing controls;
- process or organizational conditions; and
- unresolved alternatives.

The report MUST NOT convert sequence, correlation, ATT&CK mapping, reputation,
or recurrence similarity into causal or actor proof.

## 12. SOC decision-time review

The review MUST reconstruct the evidence available at the decision timestamp,
including telemetry freshness and connector delay.

It MUST consider:

- queue pressure and workload;
- time available;
- playbook and policy version;
- automation-generated notes or recommendations;
- handoffs and ownership;
- missing or delayed evidence;
- whether relevant evidence was reasonably discoverable;
- individual actions; and
- systemic staffing, tooling, telemetry, training, and process conditions.

The report MUST distinguish:

- `reasonable_with_available_evidence`;
- `questionable_with_available_evidence`;
- `not_assessable`;
- and outcome quality observed only with hindsight.

These labels are report fields, not disciplinary findings.

## 13. Detection, automation, and recurrence review

`Detection Audit` SHOULD trace:

- source events;
- historical rule or query;
- rule version and execution health;
- alert generation;
- entity mapping;
- grouping or correlation;
- enrichment;
- suppression;
- incident creation;
- automation;
- incident updates; and
- closure.

Historical evaluation MUST use bounded ad hoc query reconstruction rather than
production detection replay.

`Automation Provenance` is triggered by automated recommendations, notes,
executions, retries, overrides, or handoffs. It MUST record actor, version,
input references, output, execution state, human action, override, retry, and
handoff.

`Recurrence and Related-Incident Review` MUST state the searched scope and
coverage. It SHOULD include closed, suppressed, duplicate, split, merged, and
cross-product records when authorized and available.

Relatedness MUST state whether it is based on shared entity, infrastructure,
behavior, rule, control gap, or upstream evidence. It MUST NOT assert a campaign
or actor without additional evidence.

## 14. Containment and recovery review

This section is triggered when containment or recovery occurred, was proposed,
or is materially relevant.

It MUST distinguish observed actions from recommended actions and review:

- authority;
- necessity and proportionality;
- timing;
- evidence preservation;
- reversibility;
- service impact;
- persistence removal;
- credential or session considerations;
- restoration integrity;
- recurrence monitoring; and
- unresolved recovery proof.

The auditor MUST NOT execute any action.

## 15. Privacy, business, and legal facts

`Privacy and Evidence Handling` MUST state:

- minimum-necessary scope;
- pseudonymization state;
- de-anonymization authority, if any;
- protected-store use;
- access and export restrictions;
- handling markings;
- identity-revealing data routing; and
- telemetry-only intent limitation.

`Business and Legal Fact Packet` is triggered when technical facts may affect
service, confidentiality, integrity, availability, recoverability, privacy,
contract, regulation, notification, HR, or legal review.

It MUST contain observed facts, provenance, uncertainty, affected business
context, and the authorized human route.

It MUST NOT determine materiality, liability, legal obligation, notification,
discipline, responsible person, or intent.

## 16. Recommendations

Every recommendation MUST be:

- labeled `recommendation`;
- non-executable;
- linked to evidence, a gap, or a risk;
- assigned a proposed human owner;
- assigned a priority rationale;
- explicit about required authorization;
- explicit about expected evidence after completion; and
- separated from observed actions.

The report MUST NOT imply that a recommendation has been approved or completed.

## 17. Independent QA

`Independent QA` MUST include:

- QA rubric and version;
- citation-completeness result;
- fact, inference, assumption, and recommendation separation result;
- coverage and limitations result;
- enum and schema result;
- safety-policy result;
- privacy result;
- contradiction review;
- unsupported-certainty review;
- original-versus-auditor comparison review;
- reviewer verdict;
- disagreement or adjudication state; and
- known residual limitations.

If no independent reviewer was available, the section MUST say so and use
`section_status: partial`; it MUST NOT fabricate independence.

## 18. Stop receipt and errors

The report MUST reproduce the complete
[stop receipt](operating-contract.md#16-stopping-contract).

It MUST clearly distinguish:

- evidence sufficiency from circuit-breaker termination;
- coverage boundary from source success;
- quota from project budget;
- duplicates from novel evidence;
- low novelty from unresolved material frontier; and
- configured thresholds from universal claims.

Every error MUST use the
[stable error envelope](operating-contract.md#17-error-contract).

A report with errors MAY still contain valid findings and fully executed
sections, but each affected section MUST report the honest
`evidence_completeness` and MUST NOT present partial evidence as complete.

## 19. Citations and analytic language

Every material factual or analytic claim MUST cite evidence IDs inline.

Recommended Markdown forms are:

- `Observed: ... [E-004, E-009]`
- `Inference: ... [E-004, E-012; reasoning H-002]`
- `Assumption: ... [A-003]`
- `Recommendation: ... [RISK-002; evidence E-014]`

Likelihood and analytic confidence MUST be separate fields and separate prose.

Source dependence MUST be visible. Multiple product records derived from one
upstream event MUST not be described as independent corroboration.

## 20. Machine-readable schema contract

The JSON root MUST validate against
[audit-output.schema.json](audit-output.schema.json). It contains the 19 stable
collections defined in
[Output record families](operating-contract.md#10-output-record-families) and
one `sections` array. The `sections` array is the canonical section-order
representation; root object-member order has no meaning.

`sections` MUST contain exactly 21 entries. Entries MUST be sorted by ascending
`ordinal`, use every `section_id` exactly once, and match the ordinal and exact
`collection_refs` sequence in
[Stable section ordering](#4-stable-section-ordering). No other section entry
is permitted.

Each `sections` entry MUST contain:

| Field | Requirement |
|---|---|
| `section_id` | Exact stable identifier from the ordering table. |
| `ordinal` | Exact integer from 1 through 21. |
| `section_status` | Closed execution-status enum from the vocabulary artifact. |
| `evidence_completeness` | Closed evidence-sufficiency enum from the vocabulary artifact. |
| `behavior_bases` | Sorted-unique aggregate of authoritative claim- and record-level bases. |
| `summary` | Redacted, human-readable summary. |
| `collection_refs` | Exact ordered array of root collection names from the ordering table. |
| `claim_ids` | Material claims represented by the section. |
| `evidence_ids` | Direct supporting or contradicting evidence. |
| `gap_ids` | Coverage or capability gaps affecting the section. |
| `error_ids` | Related errors. |

Structured records MUST remain in the 19 canonical root collections rather
than being duplicated inside `sections`. Section ID arrays and record-level
cross-references provide the join to specific records. An empty referenced
collection does not remove the reference; the section status, summary, gaps,
and errors MUST explain the absence.

Null is never a substitute for unavailable information. Required fields MUST
be present with their declared JSON type. Optional unavailable values MUST be
absent and their effect represented through a gap, coverage receipt, or error.
The root and structural objects reject additional properties; detailed
algorithmic records remain extensible only where the schema explicitly permits
additional properties. Missing required fields, unknown major versions, and
unknown closed-enum values MUST be rejected.

## 21. Human-readable Markdown contract

The Markdown report MUST:

1. render headings in section ordinal order using the versioned locale label
   map and its default-locale fallback;
2. state section status near each heading;
3. use tables for coverage, evidence, hypotheses, original-versus-auditor
   comparison, errors, and stop receipt when tables improve clarity;
4. keep protected evidence out of the report;
5. preserve audit-local citations;
6. label observed and recommended content explicitly; and
7. state all material limitations before recommendations.

## 22. Prohibited report behavior

The report MUST NOT:

- treat the original incident classification as ground truth;
- hide denied, failed, partial, truncated, throttled, or malformed retrieval;
- claim nonoccurrence outside verified coverage;
- merge entities solely by hostname, display name, address, or raw process ID;
- overwrite raw Unicode or time values with normalized values;
- infer a responsible human or intent from technical telemetry alone;
- claim formal probability without a validated model;
- claim universal numeric limits or saturation thresholds;
- present preview or unverified capabilities as guaranteed;
- present similarity as campaign or actor proof;
- use hindsight to assign original analyst knowledge;
- represent recommendations as actions;
- make unsupported legal, business, materiality, notification, disciplinary,
  liability, or HR determinations; or
- fabricate QA independence, evidence, coverage, or a stop receipt.

## 23. Conformance checklist

A conforming report:

- has both JSON and Markdown forms;
- contains exactly 21 `sections` entries with ordinals 1 through 21;
- uses every stable `section_id` once and matches the exact collection mapping;
- renders Markdown headings in ascending `ordinal` order;
- marks required and conditional sections correctly;
- cites every material claim;
- separates likelihood from analytic confidence;
- separates observed, inferred, assumed, and recommended content;
- compares original and auditor assessments;
- exposes coverage and limitations;
- preserves decision-time fairness;
- contains no unsupported legal, business, disciplinary, attribution, or intent
  determination;
- includes QA; and
- ends with a complete, non-fabricated stop receipt and error disclosure.
