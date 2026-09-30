# Lifecycle-Aware Entity Resolution

## Purpose

Lifecycle-aware resolution prevents reused names, recycled identifiers, and
administrative changes from being mistaken for continuous identity. It extends
[entity-resolution.md](entity-resolution.md) and remains subordinate to
[operating-contract.md](operating-contract.md).

This reference implements Task 6 methodology for R-020, R-021, R-028, R-040,
and R-042. It is project policy unless a record explicitly cites a stronger
operation-specific basis.

## Lifecycle events

The entity kernel MUST support these lifecycle event types:

| Event | Continuity rule |
|---|---|
| `rename` | Preserves continuity only when a stable identifier or authoritative change record spans the rename. |
| `disable` | Does not break technical identity by itself, but creates an inactivity and custody interval. |
| `delete` | Breaks continuity unless a protected source proves soft-delete restoration of the same stable ID. |
| `recreate` | Breaks continuity when the stable object ID changes, even when the same UPN, name, or hostname is reused. |
| `reimage` | Usually breaks device continuity unless strong device or management evidence spans the rebuild. |
| `vdi_reset` | Requires pool, session, assignment, and time-window evidence before linking activity to a user or device. |
| `secret_rollover` | Preserves application identity only when object ownership and credential lineage are evidenced. |
| `certificate_rollover` | Preserves certificate-based continuity only when subject, issuer, thumbprint change, and rollover evidence are recorded. |
| `tenant_transfer` | Requires explicit custody and authorization evidence; similarity alone is insufficient. |
| `ownership_change` | Preserves technical resource identity but changes attribution and scope boundaries. |

Each event MUST include event time, affected entity, event type, provenance
evidence IDs, and protected references for previous and new values when present.

## Recreated accounts

A recreated account with the same UPN but a different Entra object ID is NOT
identity-continuous. The reused UPN MAY be recorded as alias history, but any
pre-recreation and post-recreation actions MUST remain distinct unless a human
review separately links responsibility.

When before and after object IDs are both known and differ, the lifecycle
decision MUST be non-continuous for every lifecycle event type. Supporting
device, hostname, or other identifiers MUST NOT override an object-ID
contradiction.

## Device reimage and rename

A device rename alone is weak. A device reimage or VDI reset MUST be treated as
a continuity break unless strong evidence bridges the event. Examples of strong
bridging evidence include stable device ID, MDE machine ID, management inventory
lineage, signed deployment record, or hardware/workload custody evidence.

Hostname reuse, DHCP address reuse, asset tag text, or display name alone MUST
NOT preserve device continuity across reimage, reset, or rebuild.

## Temporal ownership

Ownership records MUST include validity windows. The auditor MUST resolve weak
identifiers at the observed event time, not at retrieval time. If the ownership
window is unavailable, overlapping, or contradicted, the continuity record MUST
state `is_continuous: false` or record the issue as unresolved rather than
silently merging entities.

## Secret, certificate, and application continuity

Credential rollover changes the credential, not automatically the application or
service principal. Application continuity requires stable object identity and
ownership evidence. Certificate continuity requires thumbprint and certificate
context; the thumbprint itself is a strong credential identifier, but a new
thumbprint after rollover MUST be linked by rollover provenance before being
reported as continuous.

## Provenance and reversal

Every lifecycle continuity decision MUST cite evidence IDs and protected
references. A later correction MUST create a new split or continuity record that
references the prior decision. The auditor MUST preserve the prior record for
review and must not rewrite history. Kernel-generated resolution and continuity
IDs MUST be stable IDs derived from record inputs, not random GUIDs. Undo or
split records MUST list resulting entity IDs as separate valid identifiers and
MUST NOT serialize comma-joined entity IDs.

## Human attribution boundary

Lifecycle continuity is technical continuity. It does not establish human
intent, accountability, policy violation, materiality, or legal responsibility.
Those determinations are outside this kernel and require authorized human
review.
