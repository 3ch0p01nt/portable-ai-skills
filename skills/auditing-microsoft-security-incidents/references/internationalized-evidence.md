# Internationalized Evidence

Internationalized identifiers are evidence. The auditor MUST preserve the raw value exactly as acquired in the protected evidence store and MUST store only protected references or digests in ordinary report records.

## Normative rules

- Raw Unicode, IDN, localized display names, filenames, usernames, URLs, and domains MUST remain unchanged in the protected evidence ledger. Ordinary kernel and report output MUST NOT expose raw identifiers; it MUST use `protected-evidence:` references and SHA-256 digests.
- Comparison logic MUST use normalized forms internally: NFC, NFKC, invariant case-folding, and IDN A-labels for domain comparison. Output MUST publish digests of those forms rather than the normalized strings.
- Domain records MUST use `System.Globalization.IdnMapping` semantics in the deterministic kernel and MUST compare domains on A-label form when available.
- Failed domain IDN conversion MUST emit `idn_conversion_state: conversion_failed` and MUST NOT emit an empty A-label.
- NFKC compatibility changes MUST be flagged as `compatibility-lookalike`.
- Bidirectional controls U+061C, U+202A through U+202E, U+2066 through U+2069, U+200E, and U+200F MUST be flagged and rendered by code point metadata.
- Invisible and zero-width format characters including U+00AD, U+180E, U+200B through U+200F, U+2060 through U+2064, and U+FEFF MUST be flagged by code point metadata.
- Mixed-script labels, especially Latin plus Cyrillic or Greek, MUST be marked as potential homograph evidence, not silently merged with ASCII lookalikes.
- Filename values containing right-to-left override and a terminal ASCII extension MUST be flagged for extension-spoofing review.
- Locale-sensitive case behavior MUST NOT control comparison. The kernel MUST use invariant culture and MUST flag records where the configured locale would fold differently, including Turkish dotted and dotless i cases.
- Localized timestamp parsing is out of scope for this record family and MUST defer to [timeline-and-deduplication.md](timeline-and-deduplication.md).
- Unicode and IDN observations MUST remain evidence and MAY support entity-resolution review, but they MUST NOT alone establish human attribution or intent.

## Record shape

The internationalized identifier record is defined by `references\kernel\internationalized-identifier.schema.json`. It records a protected raw-value reference, raw and normalized digests, detected scripts, mixed-script state, NFKC compatibility changes, bidi controls, invisible characters, curated confusable skeleton digest, locale used, homograph risk, extension-spoofing state, limitations, and behavior bases.

The record can be carried inside an evidence record `normalized_value` or referenced from entity-resolution records without exposing the raw evidentiary text required by [operating-contract.md](operating-contract.md) and [report-contract.md](report-contract.md).

## Source and behavior basis

Requirement `R-042` is currently ineligible for freeze because the claim-content gate did not pass, but the methodology is accepted. Outputs using this record SHOULD label behavior as `configurable_project_policy`. The curated confusable map is also an `explicit_gap` because it is not the full Unicode TR39 table.

## Known gap

The deterministic PowerShell kernel implements a small curated confusable map for common Latin lookalikes in Cyrillic and Greek. It is not the full Unicode TR39 table and MUST NOT be represented as complete confusable coverage. A future shared-file change may add a versioned full-table generator after source review and fixture approval.