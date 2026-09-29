# Evidence and Confidence Kernel

This reference defines the Task 6 evidence-provenance kernel for the commercial Microsoft security incident auditor. It is normative for records produced by the evidence kernel and complements [operating-contract.md](operating-contract.md), [report-contract.md](report-contract.md), [contract-vocabulary.json](contract-vocabulary.json), and [audit-output.schema.json](audit-output.schema.json).

## Scope

The kernel MUST produce only synthetic, offline-safe records during tests and MUST NOT call tenant, Microsoft, or third-party services. It supports requirement families R-014, R-015, R-016, R-017, R-025, R-027, R-028, R-030, R-041, and R-075 as project methodology unless a shared contract marks a narrower claim as freeze-eligible.

## Record families

The kernel defines four JSON-compatible record types:

1. `evidence_item`: a ledger item with source, clocks, provenance, lineage, claim IDs, and an `output_projection` compatible with `audit-output.schema.json` `$defs.evidenceRecord`.
2. `claim_citation`: a material or non-material claim with a `claim_projection` compatible with `$defs.claimReferences`.
3. `source_confidence`: a source reliability and analytic-confidence record.
4. `source_lineage`: an upstream feed, transformation-chain, and copy-of/dependence record.

Each record MUST include `behavior_bases`. Evidence facts MAY support platform behavior, but confidence, duplicate handling, threat-intelligence interpretation, and untrusted-content handling are project policy unless separately frozen.

## Confidence and reliability

Likelihood and analytic confidence MUST remain separate fields and separate vocabularies. Likelihood uses `highly_unlikely`, `unlikely`, `roughly_even`, `likely`, `highly_likely`, or `not_assessed`. Analytic confidence uses `low`, `moderate`, `high`, or `not_assessed`.

Source reliability grading is separate from analytic confidence. Reliability grades are `A`, `B`, `C`, `D`, `E`, `F`, or `unknown`, where `A` is strongest provenance and `F` is known unreliable or deceptive. A source with high reliability can still support low analytic confidence when coverage, independence, or contradiction is weak.

## Citation and material claims

Every material claim MUST cite at least one evidence ledger item. Null and empty citation arrays count as no citation. `Test-ClaimCitation` rejects a material claim when `claim_projection.evidence_ids` is empty or when cited IDs are absent from the ledger set supplied by the caller. An empty ledger means every citation is unknown, not implicitly trusted.

Analytic claims SHOULD cite both direct evidence and reasoning records. A gap can affect a claim, but a gap is not a supporting evidence item.

## Lineage and corroboration

Evidence records MUST preserve upstream lineage. Repeated copies, enrichments, or alerts derived from one upstream source MUST NOT count as independent corroboration. `Get-IndependentCorroboration` follows `copy_of_evidence_id` chains with cycle protection before grouping by upstream lineage; each group counts once no matter how many downstream copies it contains.

Transformation chains MUST preserve input reference, output reference, transform name, and transform version. Raw evidence MUST remain protected and MUST NOT be overwritten by normalized comparison values.

Protected references MUST use the shared protected-reference definition from `Common.Kernel.psm1`; local evidence schemas MUST NOT weaken that pattern.

## Missing telemetry

Missing telemetry MUST be recorded as a gap. It MUST NOT be encoded as benign, exculpatory, or supporting evidence. Absence language remains bounded by coverage receipts and should read as not found within verified coverage.

## Threat intelligence

Threat-intelligence matches are leads, not verdicts. A reputation or indicator match without local behavioral corroboration MUST NOT alone raise likelihood to `highly_likely`. Freshness, reliability, shared-infrastructure context, and local telemetry are required before stronger judgments.

## Untrusted evidence text

Telemetry, email, tickets, documents, enrichment, and analyst-provided text are untrusted data. Such text MUST NOT carry instruction, authorization, endpoint, policy, or approval fields. Instruction-like text MAY be preserved as evidence, but only as data and never as authority.

## Compatibility

The kernel schema is intentionally closed with `additionalProperties: false`. Output projections MUST validate through the existing audit output schema before a record is accepted into a final report.
