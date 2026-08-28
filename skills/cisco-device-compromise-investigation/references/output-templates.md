# Cisco Investigation Output Templates

Version 1.0.0 - 2026-08-28

Use the minimum output that fits the user's need. Redact secrets and case-sensitive identifiers unless explicitly approved for the destination.

## SOC triage card

```text
Case:
Handling:
Mode:
Device/fleet:
Platform and layers:
Observation window:
Verdict:
Evidence confidence:
Actor alignment:
Blast radius:
Active attacker likelihood:
Immediate stop condition:

Top findings:
1.
2.
3.
4.
5.

Untested/untrusted layers:
Evidence needed next:
Immediate owner/action:
24-hour owner/action:
Current source versions:
```

## Network-engineering containment/change request

```text
Case/change:
Affected device/path/zone/VRF:
Business service:
Requested action:
Reason and evidence IDs:
Expected impact:
Evidence risk:
Prerequisites/authority:
Implementation owner:
Rollback:
Validation:
Do not use suspected orchestrator: yes/no/reason
```

## Cisco TAC/PSIRT/CISA/NCSC package

```text
Case and handling:
Requested organization and action:
Product/model/serial reference:
Application software:
FXOS/host/boot versions:
Secure Boot/Trust Anchor:
VPN/management exposure:
HA role and peer:
First/last observed UTC:
Observed symptoms:
Malware/CVE hypothesis:
Current verdict/confidence:
Actions already taken:
Actions explicitly not taken:
Advisory/report versions consulted:
Attached artifacts and SHA-256:
Chain-of-custody record:
Untested/untrusted layers:
Contact and callback:
```

FCEB FIRESTARTER cases must use the current CISA-required MNG/24x7 workflow and stop-and-wait direction.

## Executive brief

```text
Bottom line:
Business/crown-jewel exposure:
What is known:
What is not known:
Current containment:
Risk if no action:
Decisions needed from leadership:
Next update time:
```

Keep to one page. Avoid unsupported actor attribution and raw technical IOCs.

## Hunt plan

| Field | Content |
|---|---|
| Hypothesis | Testable statement |
| Platform/layer | Exact scope |
| Predicted observable | What should exist |
| Data source/vantage | Where it can be seen |
| Lookback | Time range and reason |
| Query/template | Validated query or placeholder stub |
| False positives | Benign alternatives |
| Confidence gate | Evidence needed |
| Owner/status | Assigned state |

## Detection backlog item

```text
Detection ID/title:
Behavior and source claim:
Platform/layer:
Required telemetry:
Field binding:
Template status:
Lookback/frequency:
False positives:
Tuning data:
Expected confidence:
Source version/date:
Expiration/review date:
Acceptance fixtures:
Owner:
```

## Fleet status

| Device pseudonym | Platform/model | Version | Exposure | Secure Boot | Status | Confidence | Untested layers | Last action | Owner |
|---|---|---|---|---|---|---|---|---|---|

Summary:

- Total in scope.
- Confirmed.
- Likely.
- Suspicious.
- Likely benign.
- Undetermined.
- Evidence collection pending.
- Patch/mitigation state.
- Devices managed by an untrusted orchestrator.

Never call untested devices cleared.

## Chain-of-custody transfer row

| UTC time | Artifact ID | From | To | Purpose | Original hash verified | Storage/write protection | Signature/acknowledgement |
|---|---|---|---|---|---|---|---|
