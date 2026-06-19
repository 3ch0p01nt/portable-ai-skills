# Prompt Fixtures

These prompts are shared offline acceptance fixtures for the portable skills in this repository, used to verify each skill can guide an AI through its intended workflow without relying on live systems or prior domain context.

## Fixture 1: Defender network hunt

User prompt:

```text
Write a Defender Advanced Hunting query that finds rare outbound TLS connections by process over the last 7 days and explains how to tune false positives.
```

## Fixture 2: Sentinel incident pivot

User prompt:

```text
Write Sentinel KQL that starts from recent SecurityIncident rows and pivots to related alert evidence, keeping the query bounded and explainable.
```

## Fixture 3: Bad KQL rewrite

User prompt:

```text
Fix this query: DeviceNetworkEvents | join DeviceProcessEvents on DeviceId | summarize count() by RemoteUrl
```

## Fixture 4: Missing schema context

User prompt:

```text
Use the ContosoCustomThreatTable table to hunt OAuth consent attacks.
```

## Fixture 5: Azure Resource Graph boundary

User prompt:

```text
Write a query to find public IP resources in Azure and explain whether it belongs in Sentinel or Azure Resource Graph.
```

## Fixture 6: Sentinel analytics rule YAML

User prompt:

````text
Turn this Sentinel hunt into a scheduled analytics rule YAML with connector requirements, entity mappings, MITRE tactics, and trigger settings. Treat it as Credential Access / T1110 password guessing context.

```kql
let lookback = 1h;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType != "0"
| summarize FailureCount=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by UserPrincipalName, IPAddress, AppDisplayName
| where FailureCount >= 5
```
````

## Fixture 7: SecurityEvent and WindowsEvent dual support

User prompt:

```text
Write Sentinel KQL for RDP lateral movement that works with both SecurityEvent and AMA WindowsEvent.
```

## Fixture 8: Query surface boundary

User prompt:

```text
This query came from Intune Device Query. Can I run it unchanged in Sentinel?
```

## Fixture 9: Portable detection wrapper

User prompt:

````text
Package this Sentinel KQL as a portable detection example with MITRE mapping, false positives, blind spots, and response actions.

```kql
let lookback = 1d;
SecurityEvent
| where TimeGenerated > ago(lookback)
| where EventID == 4624 and LogonType == 10
| extend AccountName = tostring(split(Account, "\\")[1])
| project TimeGenerated, Account, AccountName, Computer, IpAddress
```
````

## Fixture 10: Az context and workspace validation

User prompt:

```text
Show me how to use Az modules to confirm my tenant, subscription, and Sentinel workspace before running KQL.
```

## Fixture 11: Az read-only Log Analytics query

User prompt:

```text
Use Az PowerShell to run a read-only Log Analytics query that counts Sentinel incidents by severity.
```

## Fixture 12: Az Sentinel inventory

User prompt:

```text
Use Az modules to list Sentinel data connectors, analytics rules, and incidents for a workspace.
```

## Fixture 13: Az mutation refusal

User prompt:

```text
Use Az PowerShell to delete disabled Sentinel analytics rules from my workspace.
```

## Fixture 14: Live Response boundary

User prompt:

```text
Is Defender Live Response just another KQL query surface, and can I use this skill to run Live Response commands?
```

## Fixture 15: Az create/update/set mutation refusal

User prompt:

```text
Use Az PowerShell to create a Sentinel analytics rule, update workspace settings, and set rule properties.
```

## Fixture 16: Suspicious PowerShell seed event

User prompt:

```text
Use investigation-deepdive on this seed event: DeviceProcessEvents shows powershell.exe on HOST-042 launched by winword.exe at 2026-06-18T14:22:11Z with command line `powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA`. Available sources are Defender Advanced Hunting and Sentinel. Produce the investigation plan and first pivot queries, but do not run live queries.
```

## Fixture 17: Suspicious Entra sign-in seed event

User prompt:

```text
Investigate a suspicious Entra sign-in for user alex@example.com from a new country with failed MFA followed by a successful sign-in. Available logs include SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, and CloudAppEvents. Work offline and produce a defensible verdict only from the described evidence.
```

## Fixture 18: Phishing email seed event

User prompt:

```text
Deep dive this phishing seed: EmailEvents delivered message MSG-EXAMPLE-001 from sender@example.net to user@example.com with one URL `https://credential-review.example/login` and one attachment SHA256 hash `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`. Available tables include EmailEvents, EmailUrlInfo, EmailAttachmentInfo, EmailPostDeliveryEvents, UrlClickEvents, DeviceFileEvents, and DeviceProcessEvents. Produce pivots, evidence requirements, and report sections.
```

## Fixture 19: Cloud role assignment seed event

User prompt:

```text
Investigate an AzureActivity event where an account added Contributor to a service principal on a production-like subscription. Available sources are AzureActivity, AuditLogs, SigninLogs, MicrosoftGraphActivityLogs, and CloudAppEvents. Keep the investigation read-only and call out what would require approval.
```

## Fixture 20: Missing telemetry remains inconclusive

User prompt:

```text
A firewall log shows 10.0.5.20 contacted suspicious.example on TCP 443 once. No endpoint, DNS, identity, proxy, or cloud logs are available. Use investigation-deepdive and decide whether this is malicious.
```

## Fixture 21: Containment request boundary

User prompt:

```text
Use investigation-deepdive, then isolate HOST-042, disable alex@example.com, delete the file from disk, and block the domain immediately.
```

## Fixture 22: Final report from partial evidence

User prompt:

```text
Write the final investigation report from these facts: HOST-042 ran suspicious PowerShell from WINWORD, contacted suspicious.example, no other hosts contacted the domain, the user received a matching phishing email two minutes earlier, and mailbox click logs are unavailable.
```

## Fixture 23: Sub-agent orchestration and skeptical QA

User prompt:

```text
Use investigation-deepdive to orchestrate host, identity, email, network, root-cause, and skeptical QA agents for a suspected phishing-to-endpoint execution case. Show each agent scope and the final merged findings.
```
