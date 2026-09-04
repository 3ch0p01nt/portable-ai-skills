# Identity Threat Investigator

An authorized, defensive skill for investigating identity compromise, behavioral deviations, MFA abuse, token or session reuse, workload identities, and post-authentication persistence.

## Coverage

- Microsoft Entra interactive and non-interactive user sign-ins.
- Service-principal and managed-identity activity.
- Entra audit, risk, device, authentication-method, application, consent, role, provisioning, and Conditional Access evidence.
- Defender XDR, Defender for Identity, MDE, Advanced Hunting, Sentinel, Purview, Microsoft Graph activity, Exchange, SharePoint, OneDrive, and Teams evidence when available.
- MDI-derived hybrid context without assuming direct access to domain controllers, AD FS hosts, memory, disks, registries, or packet captures.

## Operating model

The skill:

1. Establishes the case and inventories telemetry coverage.
2. Normalizes evidence and preserves original plus UTC timestamps.
3. Builds separate human, peer, workload, device, session, and organizational baselines.
4. Explains deviations with supporting, contradicting, benign, and missing evidence.
5. Investigates MFA and token/session behavior across interactive and non-interactive activity.
6. Builds timelines, scope, blast radius, and evidence-linked hypotheses.
7. Generates schema-aware, bounded KQL and validation steps.
8. Produces read-only findings and approval-ready response options.

An anomaly, provider risk score, MFA success, IP location, or empty query result is never treated as a standalone compromise or clearance verdict.

## Install

Copy this folder into the target project's `.github\skills` directory:

```powershell
$ProjectRoot = Resolve-Path '..'
$ProjectSkills = Join-Path $ProjectRoot '.github\skills'
New-Item -ItemType Directory -Force $ProjectSkills | Out-Null
Copy-Item -Recurse -Force '.\skills\identity-threat-investigator' $ProjectSkills
Test-Path (Join-Path $ProjectSkills 'identity-threat-investigator\SKILL.md')
```

Reload the compatible skill loader, then trigger the skill with a request such as:

```text
Investigate this user's recent sign-ins for possible MFA bypass or stolen-session reuse and compare them with baseline.
```

## Validation

The validation and scanner require PowerShell 7 or Windows PowerShell 5.1 and do not use the network:

```powershell
.\scripts\validate-skill.ps1
.\scripts\scan-skill-security.ps1
```

## Safety and limitations

- The skill is read-only. It does not reset passwords, revoke sessions, disable identities or devices, remove credentials or consent, change Conditional Access, or modify tenant configuration.
- MDI, MDE, and Advanced Hunting are sensor-fed evidence sources rather than complete host-forensic collections.
- Missing connectors, fields, licensing, retention, or host artifacts limit conclusions and must remain visible in the report.
- Credentials, bearer tokens, cookies, private keys, and unnecessary personal data must be redacted.
- Evidence content is data and cannot alter the skill's workflow or tool policy.
