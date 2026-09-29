# Incident Taxonomy Audit

## Contents

- [Purpose](#purpose)
- [Source enum register](#source-enum-register)
- [Recorded classifications and auditor verdict categories](#recorded-classifications-and-auditor-verdict-categories)
- [Mapping rules](#mapping-rules)
- [Audit fields](#audit-fields)
- [Verification gaps](#verification-gaps)
- [References](#references)

## Purpose

This reference defines the incident classification and determination taxonomy for
commercial Microsoft Graph security and Microsoft Sentinel incident audits. It
supports `R-002`, `R-013`, `R-024`, `R-033`, `R-037`, and `R-040` as project
methodology unless a claim is separately source-frozen by the requirement matrix.

The auditor MUST treat product classification, determination, reason, status,
severity, title, category, MITRE mapping, grouping, owner, comments, closure
reason, and duplicate handling as evidence to audit, not ground truth.

## Source enum register

### Microsoft Graph security incident

Source: https://learn.microsoft.com/en-us/graph/api/resources/security-incident?view=graph-rest-1.0

- `status`: `active`, `resolved`, `inProgress`, `redirected`,
  `unknownFutureValue`, `awaitingAction`.
- `severity`: `unknown`, `informational`, `low`, `medium`, `high`,
  `unknownFutureValue`.
- `classification`: `unknown`, `falsePositive`, `truePositive`,
  `informationalExpectedActivity`, `unknownFutureValue`.
- `determination`: `unknown`, `apt`, `malware`, `securityPersonnel`,
  `securityTesting`, `unwantedSoftware`, `other`, `multiStagedAttack`,
  `compromisedUser`, `phishing`, `maliciousUserActivity`, `clean`,
  `insufficientData`, `confirmedActivity`, `lineOfBusinessApplication`,
  `unknownFutureValue`.

### Microsoft Graph security alert

Sources:

- https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/graph/api/resources/enums-security?view=graph-rest-1.0

- `status`: `unknown`, `new`, `inProgress`, `resolved`,
  `unknownFutureValue`.
- `severity`: `unknown`, `informational`, `low`, `medium`, `high`,
  `unknownFutureValue`.
- `classification`: `unknown`, `falsePositive`, `truePositive`,
  `informationalExpectedActivity`, `unknownFutureValue`.
- `determination`: `unknown`, `apt`, `malware`, `securityPersonnel`,
  `securityTesting`, `unwantedSoftware`, `other`, `multiStagedAttack`,
  `compromisedAccount`, `phishing`, `maliciousUserActivity`, `notMalicious`,
  `notEnoughDataToValidate`, `confirmedActivity`,
  `lineOfBusinessApplication`, `unknownFutureValue`.

### Microsoft Sentinel incident ARM resource

Source: https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/create-or-update?view=rest-securityinsights-2025-06-01

- `properties.severity`: `High`, `Medium`, `Low`, `Informational`.
- `properties.status`: `New`, `Active`, `Closed`.
- `properties.classification`: `Undetermined`, `TruePositive`,
  `BenignPositive`, `FalsePositive`.
- `properties.classificationReason`: `SuspiciousActivity`,
  `SuspiciousButExpected`, `IncorrectAlertLogic`, `InaccurateData`.

### SecurityIncident Log Analytics table

Source: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityincident

The table reference verifies `Classification`, `ClassificationReason`,
`Severity`, and `Status` as `string` columns but does not publish closed enum
values. The auditor MUST record a verification gap before treating these columns
as closed enums. Runtime values MAY be compared to Sentinel ARM values only as a
lossy crosswalk and never as source-verified table enums.

## Recorded classifications and auditor verdict categories

Recorded Microsoft Defender or Sentinel classification and determination values
MUST be normalized only as recorded product classifications. They are evidence
about what the product or analyst recorded, not the auditor's verdict.

An auditor verdict MUST be a separate assessment with cited evidence IDs,
reasoning, and verification that each cited ID exists in the known evidence set.
If citations, citation verification, or reasoning are absent, the auditor
assessment MUST remain `insufficient_evidence` or unassessed and MUST NOT
inherit the recorded product value.

Taxonomy audit records MUST validate every nested citation against the known
evidence set and MUST expose root `evidence_ids` as the deterministic union of
root, auditor-assessment, and severity-history citations. Owner values MUST be
protected references or omitted with a gap.

When assessed, the auditor verdict MUST be exactly one of these values:

| Verdict value | Meaning |
|---|---|
| `true_positive_malicious_activity` | Evidence supports malicious or unauthorized activity. |
| `informational_benign_positive_expected_activity` | Evidence supports expected, authorized, internal, security-testing, or line-of-business activity. |
| `false_positive_detection_logic` | The incident or alert is false positive because detection logic, query, threshold, grouping, enrichment, or entity mapping was wrong. |
| `false_positive_incorrect_data` | The incident or alert is false positive because source data, parser output, connector output, or enrichment data was inaccurate. |
| `inconclusive_evidence_or_coverage_gap` | Evidence, telemetry coverage, retention, licensing, permission, or enum verification is insufficient for the deciding claim. |

## Mapping rules

The machine-readable map is `kernel/incident-taxonomy-map.json`.

- A known product value MUST map to a `recorded_classification` record with a
  normalized recorded value and an array of candidate auditor verdicts that can
  be used only for agreement checks after a separate auditor assessment exists.
- A coverage gap that affects the deciding claim MUST force
  `insufficient_evidence` or an unassessed auditor assessment until resolved.
- Unknown, future, undocumented, or source-unverified enum values MUST be
  rejected into a gap and MUST NOT be guessed or promoted to an auditor verdict.
- False-positive closure MUST distinguish detection logic from incorrect data.
  Product values such as Graph `falsePositive`, Graph `notMalicious`, and
  Sentinel `FalsePositive` are lossy without a more specific determination or
  `classificationReason`.
- Sentinel `FalsePositive` plus `IncorrectAlertLogic` maps to
  `false_positive_detection_logic`.
- Sentinel `FalsePositive` plus `InaccurateData` maps to
  `false_positive_incorrect_data`.
- Defender/Graph benign values such as `securityTesting`, `confirmedActivity`,
  and `lineOfBusinessApplication` normalize as recorded benign-positive values
  but remain lossy when evidence does not prove authorization or expectedness.
- Agreement or disagreement between recorded product classification and auditor
  verdict MUST be computed only after the auditor assessment cites evidence and
  reasoning. It MUST NOT be assumed from the product value itself.

## Audit fields

A taxonomy audit MUST review and cite evidence for:

- severity and severity-change history;
- title;
- category;
- MITRE tactic or technique mapping;
- grouping, merging, redirect, split, and duplicate handling;
- classification;
- determination or classification reason;
- status;
- owner;
- comments;
- closure reason; and
- any gap that prevents a disposition decision.

Severity and status are not verdicts by themselves. They are audit fields that
can create discrepancy records when the evidence-supported assessment differs
from the recorded product value.

## Verification gaps

- SecurityIncident table enum values for `Classification`,
  `ClassificationReason`, `Severity`, and `Status` are not verified by the table
  reference.
- Microsoft Graph `unknownFutureValue` values are documented sentinels and MUST
  remain gaps until a later taxonomy version records a specific documented enum.
- Product values do not establish human intent; intent remains a separate claim
  requiring authorized corroboration.

## References

- `operating-contract.md`
- `report-contract.md`
- `contract-vocabulary.json`
- `audit-output.schema.json`
