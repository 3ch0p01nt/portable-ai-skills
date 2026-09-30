# Investigation Quality Assurance

This reference defines the project policy for independent QA of a Microsoft security incident audit. It is compatible with the `qa_records` output family and the `independent_qa` report section.

## Normative basis

- The operating boundary in [operating-contract.md](operating-contract.md) remains authoritative for commercial-only, tenant-security-state non-mutating behavior.
- The output requirements in [report-contract.md](report-contract.md) remain authoritative for the Independent QA report section.
- Controlled vocabulary values MUST come from [contract-vocabulary.json](contract-vocabulary.json) where a closed enum exists.
- The QA method implements project methodology from `R-043`. Supporting related project policies include `R-015`, `R-025`, `R-027`, `R-028`, `R-033`, `R-039`, and `R-042`.

## Independent reviewer requirement

A QA reviewer MUST record role, reviewer ID, rubric ID, rubric version, and an independence basis. A reviewer is not independent when the reviewer authored the audit, materially contributed to the audit, supervised the audit verdict, or shared the investigation context being reviewed. If no independent reviewer is available, the QA record MUST use `reviewer_verdict: not_independent` or a partial section status rather than fabricating independence.

Comparison finalization MUST re-check reviewer independence using ordinal identifier comparison between the audit author and reviewer. A non-independent reviewer blocks final status and requires human adjudication before the QA result can be treated as complete.

## Sealed verdict workflow

The reviewer MUST seal their verdict before seeing the original audit comparison. The sealed verdict MUST include:

1. `sealed_at` in RFC3339 UTC form.
2. Canonical JSON content using sorted object properties and preserved array order.
3. A SHA-256 digest over that canonical JSON.
4. Later `revealed_at` and `compared_at` timestamps.

The seal time MUST precede both reveal and comparison time. The digest MUST match the sealed content. A mismatch invalidates the sealed-verdict control and MUST be recorded as a QA failure.

Comparison finalization MUST recompute the sealed digest from the current sealed content before comparing verdict fields. The comparison reviewer verdict MUST be canonically identical to the sealed verdict content; any mismatch is tampering or record corruption that blocks finalization. Canonical JSON MUST use the shared kernel canonicalization primitive, including null support, nested array preservation, empty array preservation, ordinal key ordering, invariant number formatting, and rejection of DateTime values that were not preserved as original RFC3339 strings.

## Compared fields

QA comparison MUST cover at least:

- severity or severity band;
- disposition;
- causal edges, especially root-cause edges;
- SOC handling quality; and
- containment or recovery validity.

Disagreements MUST be classified as `material` or `minor`. Disposition disagreement, severity-band disagreement, or a different root-cause edge is material. Material disagreement MUST route to a human adjudicator, set adjudication state to `pending`, and block final status until resolved. SOC quality and recovery validity disagreements SHOULD be recorded and MAY become material by local policy, but they do not automatically block final status under this kernel rule.

## Rubric preservation and version mismatch

The QA record MUST preserve both the reviewed audit rubric version and the reviewer rubric version. Comparison across rubric versions MUST be flagged. A version mismatch is not itself proof that either reviewer is wrong, but it is a calibration limitation that humans can weigh during adjudication.

## Calibration metrics

Calibration records SHOULD include categorical percent agreement and Cohen's kappa for disposition labels. Metrics MUST state their scope, item count, categories, and rubric versions. Metrics are calibration evidence, not an autonomous override of a sealed review or human adjudication.

## Skeptical-evidence QA checklist

The independent reviewer MUST challenge evidence integrity before accepting the audit result. The checklist MUST include:

- forged or decoy telemetry;
- poisoned baselines, including attacker dwell time inside the baseline window;
- false flags in tooling, infrastructure, language, or enrichment;
- duplicated upstream feeds counted as independent corroboration;
- prompt injection in evidence, including email, log, ticket, document, URL, User-Agent, username, and enrichment content;
- missing telemetry represented as a gap rather than benign evidence;
- unsupported certainty, especially attribution, intent, accountability, business materiality, legal obligation, and recovery completion; and
- raw Unicode, localized values, and normalized comparison values kept separate.

## Output compatibility

Kernel QA records MUST include the audit-output `qaRecord` core fields: `qa_id`, `rubric_version`, `reviewer_verdict`, `adjudication_state`, `checks`, `limitations`, `claim_ids`, `evidence_ids`, `gap_ids`, `error_ids`, and `behavior_bases`. Additional QA details MAY be projected into the extensible audit output record, but the kernel schema remains closed for deterministic validation.
