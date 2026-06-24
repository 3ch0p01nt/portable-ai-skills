# Public Source Notes

These notes summarize public sources for offline skill grounding. They are not a substitute for current product documentation during live operations.

## MITRE ATT&CK Enterprise Tactics

Source: `https://attack.mitre.org/tactics/enterprise/`

MITRE ATT&CK tactics describe the adversary's tactical goal, or why an action is performed. Use tactics as a reasoning aid for categorizing observed behavior, not as proof of maliciousness by itself.

Common tactics relevant to investigations include initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, command and control, exfiltration, and impact.

## Microsoft Sentinel Incidents

Source: `https://learn.microsoft.com/en-us/azure/sentinel/investigate-incidents`

Microsoft Sentinel incidents aggregate relevant evidence for investigations. Incidents can contain alerts, entities, severity, status, tactics, and techniques. Treat an incident as a case container and starting point, not as complete proof.

## Microsoft Sentinel Entities

Source: `https://learn.microsoft.com/en-us/azure/sentinel/entities`

Sentinel uses entities to classify data elements such as accounts, hosts, mailboxes, IP addresses, files, cloud applications, processes, URLs, and Azure resources. Use entities as pivot anchors across alerts, logs, and investigation threads.

## Microsoft Sentinel Data Connectors

Source: `https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference`

Sentinel table availability depends on enabled data connectors and workspace configuration. Do not assume a table exists solely because it is useful. If a required connector or table is missing, mark the telemetry gap and provide a validation query or inventory check.

## Microsoft Defender XDR Advanced Hunting

Source: `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview`

Defender XDR advanced hunting is query-based threat hunting over raw data for known and potential threats. Use it for endpoint, identity, email, cloud app, and Sentinel-connected hunting when available. Query results must be time-bounded and interpreted as evidence, not as automatic verdicts.
