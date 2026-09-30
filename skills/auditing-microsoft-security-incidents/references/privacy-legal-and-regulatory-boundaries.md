# Privacy, Legal, and Regulatory Boundaries

## Purpose

This reference defines privacy/access classification records for the commercial Microsoft incident auditor. It implements R-073 and the explicit human-gate boundary in G-029 while preserving [operating-contract.md](operating-contract.md), [report-contract.md](report-contract.md), [contract-vocabulary.json](contract-vocabulary.json), and [audit-output.schema.json](audit-output.schema.json).

## Normative rules

- Privacy records MUST remain compatible with `privacyRecord`.
- Access MUST be authorized, purpose-limited, role-limited, and minimum necessary.
- Pseudonymization state MUST be explicit.
- Identity-revealing data MUST be routed only to authorized recipients and protected evidence stores.
- Insider-risk records MUST reveal identity only when classification records authorize identity reveal. Otherwise, ordinary output MUST use pseudonyms and protected references.
- Export restrictions MUST state whether export is prohibited, protected-reference-only, or requires authorized privacy/legal route.
- Protected evidence MUST be referenced, never inlined.
- Telemetry alone MUST NOT establish human intent or accountability.
- A privacy packet MUST contain at least one privacy record, or it MUST explicitly record `packet_state: no_facts_provided` and `valid_for_reporting: false`. A `no_facts_provided` packet is a structured invalid result and MUST NOT be projected into a report as evidence.
- Privacy projections MUST include only the allowlisted `privacyRecord` fields. Intermediate review notes, source payloads, and other non-reporting fields MUST NOT pass through to audit output records.

## Required insider alternatives

When insider-risk, employee, contractor, or privileged-user context is present, records MUST separately consider all of these alternatives:

1. malicious intent;
2. compromised account;
3. negligence;
4. policy violation; and
5. authorized activity.

Considering these alternatives does not decide intent. It records that the audit preserved the alternatives for authorized human review.

## Identity-revealing boundary

For products or workflows that pseudonymize users, including Purview Insider Risk contexts, records MUST preserve this boundary:

- `pseudonym_only`: identity is not revealed in ordinary output;
- `identity_revealed`: allowed only when `identity_reveal_authorized` is true and the identity appears only as a protected reference; and
- raw identity values MUST NOT be inlined.

## Minimization and export

Records SHOULD state:

- purpose;
- minimization rationale;
- role-based visibility;
- export restrictions;
- protected-store use;
- identity-revealing boundaries; and
- evidence and gap references.

## Schema and validator

The packet schema is `kernel/privacy-access.schema.json`. The deterministic validator is `scripts/kernel/BusinessLegalPrivacy.Kernel.psm1` and MUST remain pure, offline, and non-mutating.
