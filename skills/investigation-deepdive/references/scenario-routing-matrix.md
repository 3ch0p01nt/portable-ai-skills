# Scenario Routing Matrix

Use this matrix to route entities to investigation scenarios. More than one scenario can apply.

| Seed pattern | Primary scenario | Entity playbooks | Initial answer shape |
| --- | --- | --- | --- |
| Domain or URL plus host or user | Web or C2 investigation | Domain or URL, host, user, process | Entity pivot packet |
| IP plus port or protocol | Network investigation | IP, host, process, user | Entity pivot packet |
| Host plus rare process | Endpoint execution | Host, process, file/hash, network | Entity pivot packet |
| User plus new country or failed MFA | Identity compromise | User, IP, device, cloud app | Entity pivot packet |
| Email message plus URL or attachment | Phishing investigation | Email, URL, file/hash, user, host | Entity pivot packet |
| Cloud role or resource operation | Cloud control-plane abuse | Cloud resource, user, service principal | Entity pivot packet |
| Service principal or app ID | OAuth or app abuse | Service principal, cloud resource, user | Entity pivot packet |
| Scheduled task, service, registry key | Persistence | Persistence artifact, host, process, file/hash | Entity pivot packet |
| Many hosts or ports with scanner note | False-positive or scanner review | IP, host, false-positive decisioning | False-positive review |
| Single signal with no process/user/source | Missing telemetry | Weak-context anomaly | Evidence collection plan |
| Request for tenant-changing action | Safety boundary | Hard safety controls | Hard-safety refusal |

## Scenario Families

1. Phishing to endpoint execution.
2. Suspicious endpoint process execution.
3. Domain, URL, or IP anomaly.
4. Identity compromise or suspicious sign-in.
5. Password spray or MFA fatigue.
6. OAuth consent or service principal abuse.
7. Azure role assignment or resource-control anomaly.
8. Lateral movement by remote access or remote execution.
9. Persistence by registry, scheduled task, service, startup folder, or WMI.
10. File/hash or malware triage.
11. Data access, collection, or exfiltration.
12. Benign admin, scanner, update, or business application activity.
13. Missing telemetry or single-signal anomaly.

## Routing Rules

- Prefer entity pivot packets for vague or early-stage inputs.
- Prefer final reports only after evidence supports a defensible verdict.
- Always route destructive action requests to hard safety controls.
- Always route known-good claims to false-positive decisioning before excluding evidence.
- If a workbook anomaly names a peer group or baseline, preserve it in the evidence ledger.