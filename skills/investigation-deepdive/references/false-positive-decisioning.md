# False-Positive Decisioning

Use this reference when the investigation might be benign, approved, noisy, or inconclusive.

## Rule

Do not apply allowlists or known-good explanations before extracting entities and scoping the activity. Known-good explanation is a hypothesis that needs evidence.

## Benign Hypotheses

Test these explanations:

- Approved admin activity.
- Software deployment or update.
- Vulnerability scanner.
- EDR or SIEM false positive.
- Business application behavior.
- Red-team or test activity.
- User mistake.
- Known-good automation.
- Monitoring, backup, or management tooling.
- CDN, proxy, VPN, NAT, or cloud-provider infrastructure.

## Evidence Needed

For each benign hypothesis, collect:

- Owner or change context.
- Host and user prevalence.
- First seen and last seen.
- Process path, signer, parent, and command-line features.
- Source IP, user agent, location, and device state.
- Similar activity in peer group.
- Alert or incident history.
- Whether the activity occurred before or after the seed.

## Decision Rules

- Benign requires evidence that strongly supports approved or expected behavior.
- Suspicious means abnormal behavior remains but proof is incomplete.
- Malicious requires clear evidence of unauthorized execution, compromise, persistence, credential abuse, exfiltration, malware, lateral movement, or confirmed threat infrastructure.
- Inconclusive means telemetry is missing or contradictory.

## Tuning Guidance

- Scope first, tune second.
- Prefer entity-specific exclusions over broad global exclusions.
- Document what evidence justified the exclusion.
- Include blind spots created by the tuning decision.
- Never suppress a pattern solely because it is noisy.