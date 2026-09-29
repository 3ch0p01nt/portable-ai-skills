# Evidence Saturation and Loop Control

This reference defines the deterministic saturation policy for commercial
Microsoft security incident audits. It is project policy, not a universal
Microsoft threshold. It supports R-031 and R-032 with the qualifications in
the source matrix and implements the stopping contract in
[operating-contract.md](operating-contract.md).

## Normative rules

1. A branch MUST maintain an investigation-branch record, bounded frontier
   records, pivot records, a saturation-state record, and a stop receipt.
2. Duplicate and equivalent-pivot detection MUST run before novelty scoring.
   A repeated upstream observation or equivalent query MUST NOT be counted as
   new evidence.
3. An equivalent query MUST NOT be repeated unless either the scope or the
   approach changes. The query signature is the deterministic combination of
   source, entity, query family, scope, and approach.
4. Novelty is present only when a nonduplicate pivot produces at least one of:
   a new material entity, causal node, causal edge, hypothesis ranking or
   confidence change, control gap, scope change, or blast-radius change.
5. A branch reaches saturation only after the configured number of consecutive
   nonduplicate zero-novelty pivots, a stable sensitivity test, and no
   unresolved material frontier.
6. Sensitivity is stable only when the leading conclusion remains unchanged
   after removing the leading evidence item and after downgrading a
   low-reliability source.
7. The frontier MUST be bounded. The auditor MUST expand an entity only when
   the entity can materially affect a hypothesis, scope, severity, root-cause,
   or control-gap conclusion.
8. Frontier priority MUST be based on expected information gain. Tier-0
   identities, critical services, recovery infrastructure, and reachable
   high-impact assets MUST retain the configured minimum priority floor even
   when expected information gain is low.
9. A hard cap is a circuit breaker only. It MUST NOT be used as the primary
   saturation rule.
10. Every branch MUST emit a stop receipt containing the trigger, measured
    thresholds, unresolved frontier, hypothesis state, and coverage
    limitations.
11. A saturation stop receipt MUST be backed by the branch saturation state.
    Missing, unknown, or unstable sensitivity state MUST block auto-stop.
12. Stop receipt `stopped_at` values MUST be supplied through a mandatory
    injected `Now` value and normalized to UTC. The kernel MUST NOT provide a
    wall-clock or hard-coded default for functions that stamp time.
13. Frontier truncation MUST report original count, included count, truncated
    count, and remaining frontier item identifiers by default.
14. The unresolved frontier MUST be preserved by default. A reset requires an
    explicit recorded reason.
15. Generated saturation and frontier identifiers MUST be deterministic stable
    IDs, not GUIDs or wall-clock values.
16. A saturation stop receipt MUST NOT contain unresolved frontier items.
17. The consecutive zero-novelty threshold MUST be at least one.

## Stop reasons

The domain stop reasons are `saturation`, `coverage_boundary`, `quota`,
`risk_budget`, and `hard_cap`. Reports MUST map them to the existing
[contract-vocabulary.json](contract-vocabulary.json) stop causes where values
already exist:

| Domain reason | Audit-output stop cause |
|---|---|
| `saturation` | `evidence_sufficient` |
| `coverage_boundary` | `coverage_boundary` |
| `quota` | `quota` |
| `risk_budget` | `budget_exhausted` |
| `hard_cap` | `circuit_breaker` |

`coverage_boundary` MUST record the missing source, affected claims, and
required follow-up. Missing telemetry is a gap, not benign evidence.

## Record compatibility

The kernel schema is
`kernel/saturation.schema.json`. Stop receipts emitted by the deterministic
kernel MUST also project to the `stopReceipt` contract used by
[report-contract.md](report-contract.md). The kernel MAY include additional
domain fields only when the audit-output schema permits additional properties.

## Safety

This logic is pure and deterministic. It MUST NOT call live tenant APIs, perform
network access, mutate tenant state, read credentials, or infer that absent data
means absent activity outside verified coverage.
