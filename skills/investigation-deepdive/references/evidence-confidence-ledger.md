# Evidence and Confidence Ledger

## Evidence Ledger Schema

Use this schema for every major finding:

| Field | Meaning |
| --- | --- |
| finding_id | Stable identifier such as `F1`, `F2`, or `F3`. |
| claim | The conclusion being supported. |
| supporting_evidence | Specific log, query result, event, timestamp, or observable. |
| source | Table, tool, report, or analyst-provided fact. |
| timestamp | Relevant event time or time range. |
| entity | Host, user, IP, process, file, URL, domain, resource, message, or alert. |
| confidence | High, Medium, Low, or Unknown. |
| mitre_mapping | MITRE ATT&CK tactic or technique when supported by evidence. |

## Confidence Levels

- High: multiple independent logs or sources support the conclusion and benign explanations are unlikely.
- Medium: evidence supports the conclusion, but one or more telemetry gaps or plausible benign explanations remain.
- Low: evidence is weak, incomplete, single-source, or compatible with several explanations.
- Unknown: telemetry is insufficient or conflicting.

## Verdict Rules

- Malicious: clear evidence of unauthorized execution, compromise, persistence, credential abuse, exfiltration, malware, lateral movement, or confirmed threat infrastructure.
- Suspicious: behavior is abnormal, risky, or partially matches malicious tradecraft, but evidence is incomplete.
- Benign: evidence strongly supports approved software, admin action, expected business behavior, or known-good automation.
- Inconclusive: telemetry is insufficient or conflicting.

## Evidence Discipline

- Never invent evidence.
- Never claim a query was executed unless it was executed in the current task or the user supplied the result.
- Label analyst-supplied facts as analyst-supplied facts.
- Label inference separately from direct evidence.
- Treat missing telemetry as a gap, not as negative proof.
- Include dead ends because they explain the scope of the investigation.
- If timestamps do not line up, lower confidence and call out the mismatch.

## Claim Review

Before finalizing, each major claim must answer:

- What exact evidence supports this?
- Which source produced the evidence?
- What entity and timestamp does it involve?
- What benign explanation could fit?
- What evidence would disprove it?
- How much telemetry is missing?