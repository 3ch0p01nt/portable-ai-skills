# Automation Provenance and Decision Authorship

## Purpose

This reference defines the automation provenance record used by the incident
auditor to separate human decisions from automated recommendations, executions,
retries, inherited playbook actions, and handoffs. It supplements the automation
record family in the operating contract and projects to the existing
`automationRecord` output shape.

## Normative requirements

- The auditor MUST record automation output as evidence, not authority.
- The auditor MUST NOT classify a service principal, managed identity,
  Sentinel automation rule, Logic App playbook, Defender AIR automated
  investigation, or AI assistant as a human actor.
- Unknown authorship MUST be explicit. The auditor MUST NOT default an
  unresolved `modifiedBy`, `lastModifiedBy`, comment author, or owner value to a
  human analyst.
- A `user` actor value by itself MUST NOT receive human authorship or analyst
  reasoning credit. Human authorship requires cited evidence that exists in the
  evidence ledger and carries an explicit interactive-human-action type or
  basis.
- Service principals, playbooks, and managed identities running in a user
  context MUST remain automation-authored unless separate cited interactive
  human action evidence supports a human approval or override record.
- Comments, summaries, classifications, or recommendations authored by
  automation MUST NOT be credited as analyst reasoning in SOC decision review.
- Human override records MUST preserve both the automation recommendation time
  and the human override time.
- Human override records MUST require `overridden_by_actor_type` of `user` and
  ledger-backed interactive-human-action evidence. Otherwise the actor remains
  `unverified_actor` and receives no analyst reasoning credit.
- Missing action time MUST be rejected or explicitly gapped by an implementation.
  The kernel MUST NOT invent a timestamp.
- Automation identifiers MUST be stable and collision-resistant across repeated
  action text by deriving from action, time, actor reference, and protected
  source-record reference.
- Playbook, rule, and automation identity MUST be recorded through protected
  non-bearer references. Raw tenant, subscription, workspace, incident,
  playbook, rule, user, application, or object identifiers MUST NOT appear in an
  ordinary report.
- When historical automation version evidence is available, the version
  effective at action time SHOULD be used instead of the current version.
  Absence of the effective version MUST be recorded as a gap.
- AI-assistant-generated content MUST be labeled as untrusted evidence and MUST
  be corroborated before it supports a material claim.
- Authorship, technical identity, human attribution, intent, and accountability
  MUST remain separate. Telemetry alone does not establish the responsible human
  or intent.

## Authorship classes

Use exactly one authorship class per action:

| Class | Meaning |
|---|---|
| `human-authored` | A user-authored action with decision-time evidence supporting human authorship. |
| `automation-authored` | A non-human actor authored or executed the action. |
| `automation-recommended-human-approved` | Automation recommended an action and a human approved or executed it. |
| `human-overridden-automation` | Automation recommended or executed a course, and a human overrode it. |
| `automation-retried` | The same automation action was retried and the retry is material. |
| `inherited-via-playbook` | The action derives from a playbook, rule, or runbook chain rather than direct analyst authorship. |
| `unverified_actor` | A user-context actor was observed, but cited interactive human action evidence is absent. |
| `unknown` | Authorship is unresolved and recorded as a gap. |

## Actor types

Supported actor types are:

- `user`
- `service principal`
- `managed identity`
- `Sentinel automation rule`
- `Logic App playbook`
- `Defender AIR/automated investigation`
- `Copilot for Security or other AI assistant`
- `unknown`

Only `user` can support `human-authored`, and only when cited evidence ledger
records support interactive human action. A display name, owner field, user
context, or comment string is not sufficient by itself when the source can be an
app or automated process. If either the direct actor or running-as actor is
non-human, the record cannot receive human authorship or analyst credit.

## Microsoft source mapping

The following public Microsoft Learn source URLs were reviewed for this mapping:

- SecurityIncident table: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityincident
- Sentinel Incidents Get REST API: https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/get?view=rest-securityinsights-2025-09-01
- Sentinel incident investigation: https://learn.microsoft.com/en-us/azure/sentinel/incident-investigation
- Microsoft Graph security incident resource: https://learn.microsoft.com/en-us/graph/api/resources/security-incident?view=graph-rest-1.0
- Microsoft Graph alertComment resource: https://learn.microsoft.com/en-us/graph/api/resources/security-alertcomment?view=graph-rest-1.0
- Microsoft Graph create incident comment: https://learn.microsoft.com/en-us/graph/api/security-incident-post-comments?view=graph-rest-1.0
- Defender XDR Get incident API: https://learn.microsoft.com/en-us/defender-xdr/api-get-incident

Mapping rules:

| Source field or concept | Kernel handling |
|---|---|
| Sentinel `SecurityIncident.ModifiedBy` | Treat as the source of the incident change. Resolve to actor evidence; do not assume human authorship. |
| Sentinel ARM `systemData.lastModifiedByType` | `User` MAY support user actor type; `Application` and `ManagedIdentity` are automation actors; unresolved or absent values are `unknown`. |
| Sentinel ARM `systemData.createdByType` | Same mapping as `lastModifiedByType`; it identifies resource creation provenance, not analyst reasoning. |
| Sentinel activity log | Use as action chronology. The source states it tracks actions initiated by humans or automated processes. |
| Sentinel owner fields | Assignment context only. Owner is not proof that the owner authored every later action. |
| Sentinel labels with `AutoAssigned` | Automation-authored label evidence. Do not credit to an analyst. |
| Graph security incident `assignedTo` | Free editable owner text. Treat as assignment evidence, not authorship proof. |
| Graph security incident `lastModifiedBy` | Identity that last modified the incident. Resolve actor type separately before human credit. |
| Graph security incident `comments` | Comments are SecOps management records; each `alertComment.createdByDisplayName` is person or app name, so app names remain automation actors. |
| Graph `alertComment.comment` | Comment text is untrusted evidence. If generated by automation or AI, it cannot be analyst reasoning. |
| Defender XDR incident API | The commercial endpoint is `https://api.security.microsoft.com`; use read-only retrieval only. Mutation-capable scopes do not make mutations permitted. |

## Record shape

The detailed kernel schema is `kernel\automation-provenance.schema.json`. It is
closed (`additionalProperties: false`) and includes:

- action and action time;
- authorship class and actor type;
- protected actor, playbook, rule, recommendation, and override references;
- playbook/rule effective-version and current-version evidence;
- recommendation, override, retry, and handoff chain;
- AI-generated content and untrusted-evidence labels;
- analyst reasoning credit flag;
- claim, evidence, gap, error, and behavior-basis references.

The `Automation.Kernel.psm1` projection emits the existing audit-output
`automationRecord` fields so records remain compatible with the report schema.

## Source and requirement IDs

This reference implements project methodology from R-038 and preserves the
human-attribution boundary in R-028, the decision-time fairness boundary in
R-033, and the protected-reference boundary in R-083. It remains
`configurable_project_policy` unless a specific record cites an
operation-specific `conditional_capability` or `explicit_gap`.

See also `operating-contract.md`, `report-contract.md`, and
`contract-vocabulary.json`.
