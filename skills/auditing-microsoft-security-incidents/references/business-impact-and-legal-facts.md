# Business Impact and Legal Facts

## Purpose

This reference defines evidence-only business-impact and legal/regulatory fact packets for the commercial Microsoft incident auditor. It implements the human-decision gates described by R-071 and R-072 and preserves the report boundaries in [operating-contract.md](operating-contract.md), [report-contract.md](report-contract.md), [contract-vocabulary.json](contract-vocabulary.json), and [audit-output.schema.json](audit-output.schema.json).

## Normative rules

- The auditor MUST record observed business and legal facts only.
- The auditor MUST NOT decide materiality, notification obligation, breach status, liability, safety impact, discipline, responsible person, or legal conclusion.
- Business-impact records MUST remain compatible with `businessFactRecord` and include critical service, dependencies, observed confidentiality/integrity/availability effects, recoverability, affected parties, affected data categories, protected evidence references, and claim citations.
- Legal/regulatory fact records MUST remain compatible with `legalFactRecord` and include data categories potentially accessed, jurisdictions indicated by evidence, timeline anchors, chain-of-custody notes, protected evidence references, human route, and determination boundary.
- Protected evidence MUST be referenced through non-bearer protected references. It MUST NOT be inlined in repository files, ordinary logs, ordinary reports, or fixtures.
- Chain-of-custody notes MUST record who preserved the reference, when it was preserved, what was preserved, and a synthetic integrity hash for the preserved reference.
- Evidence gaps MUST remain gaps. Missing telemetry MUST NOT be represented as benign evidence.
- Every material business or legal fact MUST cite audit-local evidence IDs and claim IDs.
- A business/legal packet MUST contain at least one business or legal fact, or it MUST explicitly record `packet_state: no_facts_provided` and `valid_for_reporting: false`. A `no_facts_provided` packet is a structured invalid result and MUST NOT be projected into a report as evidence.
- Report projections MUST include only the allowlisted `businessFactRecord` and `legalFactRecord` fields. Source payloads, reviewer notes, and other intermediate fields MUST NOT pass through to audit output records.

## Business-impact fact content

Business-impact packets SHOULD include these fact classes when evidence supports them:

| Fact class | Required boundary |
|---|---|
| Critical service | Name or pseudonymous service reference only; no materiality conclusion. |
| Dependencies | Observed or declared dependencies with evidence references. |
| Confidentiality effect | Observed access, exposure, or absence within verified coverage only. |
| Integrity effect | Observed modification or absence within verified coverage only. |
| Availability effect | Observed outage, degradation, throttling, or absence within verified coverage only. |
| Recoverability | Observed restore, rollback, clean monitoring, backup, or unresolved proof. |
| Affected parties and data categories | Fact labels for human review, not notification conclusions. |

## Legal/regulatory fact content

Legal/regulatory packets SHOULD include:

- data categories potentially accessed;
- jurisdictions indicated by evidence;
- timeline anchors that distinguish event time from retrieval time;
- protected evidence references;
- chain-of-custody notes; and
- the authorized human route for counsel or privacy/legal review.

## Prohibited autonomous outputs

The following fields and values are prohibited in business/legal packets. Field-name checks are recursive and normalize names by lowercasing and stripping hyphens and underscores before denylist comparison, so camelCase, snake_case, and hyphenated variants are prohibited equally.

- materiality determination;
- notification obligation;
- breach determination;
- legal conclusion;
- safety determination;
- liability determination;
- disciplinary determination; and
- intent determination.

Use `determination_boundary` values such as `requires_human_business_owner_determination` or `requires_human_counsel_determination` instead.

## Schema and validator

The packet schema is `kernel/business-legal.schema.json`. The deterministic validator is `scripts/kernel/BusinessLegalPrivacy.Kernel.psm1` and MUST remain pure, offline, and non-mutating.
