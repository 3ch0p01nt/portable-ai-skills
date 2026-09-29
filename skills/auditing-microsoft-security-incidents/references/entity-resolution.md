# Entity Resolution

## Purpose

Entity resolution records how the auditor relates users, devices, applications,
certificates, resources, sessions, network addresses, and other observables
without overstating identity. It supports the entity output family in
[audit-output.schema.json](audit-output.schema.json) and the report section in
[report-contract.md](report-contract.md).

This reference is project methodology for R-020, R-021, R-028, R-042, and the
Task 6 entity kernel. It MUST be labeled with `configurable_project_policy`
unless a record is explicitly an operation-specific `conditional_capability` or
`explicit_gap` under [operating-contract.md](operating-contract.md).

## Required records

An entity-resolution workflow MUST preserve these record types:

- `entity` record compatible with `entity_records[]` in
  [audit-output.schema.json](audit-output.schema.json).
- `entity_resolution` record with decision, confidence, basis identifiers,
  contradictions, provenance, and reversal metadata.
- `alias_history` records with validity windows.
- `lifecycle_event` records for identity, device, credential, certificate,
  application, tenant, and ownership changes.
- `identity_continuity` record stating whether the before and after subjects are
  continuous, non-continuous, or unresolved.

Raw tenant or resource identifiers MUST NOT appear inline. They MUST be stored
only as protected references compatible with `protectedReference` in
[audit-output.schema.json](audit-output.schema.json). Normalized comparison
forms MUST NOT be emitted inline when they reveal tenant, user, device, or
customer identifiers; emit a deterministic digest such as `normalized_digest`
or a protected reference instead.

## Identifier strength

Strong identifiers SHOULD drive high-confidence continuity or merge decisions
when their provenance and validity window support the claim:

| Kind | Strength |
|---|---|
| Entra object ID | strong |
| Device ID | strong |
| SID | strong |
| MDE machine ID | strong |
| Certificate thumbprint with certificate context | strong |
| Application or service-principal object ID | strong |
| Hardware or workload identity with custody evidence | strong |

Weak identifiers are lifecycle-sensitive and MUST NOT by themselves produce a
high-confidence merge:

| Kind | Strength |
|---|---|
| Display name | weak |
| Hostname | weak |
| UPN prefix or reused UPN string | weak |
| IP address, including private, NAT, VPN, proxy, or DHCP address | weak |
| Raw process ID without process creation context | weak |
| Shared infrastructure, CDN, relay, or resolver name | weak |

A weak-only match MAY remain useful as a lead, alias, or moderate/low-confidence
candidate. It MUST NOT be reported as a high-confidence technical identity.
Identifier strength MUST be derived from the identifier kind table. Caller
metadata MAY lower a normally strong kind to weak when source quality is
insufficient, but it MUST NOT raise a weak kind to strong. Contradictory strong
identifiers, such as two different protected Entra object ID references, MUST
block a merge and be reported as a distinct or unresolved resolution decision.
The kernel MUST detect such contradictions inside the full identifier set even
when callers do not pre-label them as contradictions. When normalized digests
are present for strong identifiers of the same kind, the kernel MUST compare
the digest values rather than the protected evidence references. One distinct
digest indicates agreement even when multiple independent protected references
support it; multiple distinct digests indicate contradiction. If no normalized
digest is available, differing protected references make agreement unresolved
and not-assessed rather than a confirmed strong contradiction. The same
unresolved rule applies when only some same-kind strong identifiers have
digests and the protected references differ.

## Merge, split, and distinct decisions

`decision` MUST be one of `merge`, `split`, or `distinct`.

A merge decision MUST record source entity IDs, result entity ID, basis
identifiers and strength, validity windows when known, supporting evidence,
contradictions, confidence separate from likelihood, and reversible provenance.

A split decision MUST record the prior merged entity, resulting entities, why the
prior merge no longer holds, and the provenance that supports reversal. A
`distinct` decision MUST state the collision or contradiction that prevented a
merge.

Merges and splits MUST be reversible in analysis artifacts. Reversal MUST NOT
mutate source evidence. It creates a new resolution record that points to the
prior resolution and cites new provenance.

## Temporal ownership

Weak identifiers are time-bounded. An IP, hostname, UPN string, shared mailbox,
resource alias, or display name MAY map to different principals across validity
windows. Resolution MUST evaluate the observation time against the ownership
window before using the identifier.

When windows overlap or are missing, the auditor MUST record a collision or
coverage gap. Absence of a collision record is not proof that ownership was
unique. Overlapping windows that both contain the observed time MUST return an
unresolved ownership result rather than selecting the first match.

## Unicode and internationalized identifiers

This kernel records raw versus normalized fields but does not define Unicode
normalization policy. The internationalized evidence pack owns Unicode, IDN,
confusable, bidirectional, locale, and case-folding details. Entity records MUST
preserve raw representations by protected reference and MAY point to normalized
comparison forms produced by that pack.

## Attribution boundary

Technical identity is not human attribution. Account, device, token, session,
certificate, or application evidence MUST NOT by itself establish a responsible
human, intent, accountability, HR finding, legal conclusion, or disciplinary
finding. Such claims require authorized review and separate evidence.

## Output compatibility

The entity record projection MUST include the required `entityRecord` fields in
[audit-output.schema.json](audit-output.schema.json): `entity_id`,
`entity_type`, `aliases`, `lifecycle_summary`, `attribution_boundary`,
`claim_ids`, `evidence_ids`, `gap_ids`, `error_ids`, and `behavior_bases`.
Additional entity-kernel fields MAY be present because the audit-output entity
record is explicitly extensible.
