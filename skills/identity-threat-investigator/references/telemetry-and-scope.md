# Telemetry and Scope

## Source matrix

| Question | Primary evidence | Important companion evidence |
|---|---|---|
| Who authenticated? | Interactive and non-interactive Entra sign-ins | Risk detections, Conditional Access details |
| Was an existing session or token used? | Non-interactive sign-ins and authentication details | Graph activity, CloudAppEvents, OfficeActivity |
| Did authentication configuration change? | Entra AuditLogs and authentication-method activity | Sign-ins before and after the change |
| Was a device registered or joined? | Entra AuditLogs and device records | Sign-in device context, MDE DeviceInfo |
| Was privilege changed? | Entra role and group audit events | PIM, Graph activity, affected resource activity |
| Was an app or workload identity abused? | Service-principal and managed-identity sign-ins | App audit, consent, credentials, Graph activity |
| What did the identity access? | Graph activity and Microsoft 365 audit | Exchange, SharePoint, OneDrive, Teams, CloudAppEvents |
| Is there hybrid identity evidence? | MDI alerts and Advanced Hunting identity tables | MDE device evidence and Entra correlation |

## Entra evidence families

- Interactive user sign-ins.
- Non-interactive user sign-ins.
- Service-principal sign-ins.
- Managed-identity sign-ins.
- Audit and provisioning logs.
- Risk detections and risky identities.
- Authentication-method registration and use.
- Device registration, join, ownership, compliance, and management state.
- Conditional Access policy evaluation.
- Application, service-principal, consent, owner, credential, and federated-credential changes.
- Role, PIM, group, and directory changes.

## Defender and Microsoft 365 evidence

- Defender XDR incidents, alerts, identities, devices, and cloud application activity.
- Defender for Identity alerts and identity behaviors.
- Advanced Hunting tables such as identity logon, directory, query, device, and cloud application events when present.
- Purview Audit or OfficeActivity for mailbox rules, mail access, file access, sharing, consent, and administrative operations.
- MicrosoftGraphActivityLogs for token-to-operation pivots when available.

## Hybrid boundary

MDI and MDE report selected sensor and endpoint observations. They are not complete host-forensic collections. Record these surfaces as `unavailable` unless direct artifacts are supplied:

- domain-controller Security logs outside collected events;
- AD FS host logs not ingested;
- process memory;
- disks and browser stores;
- packet capture;
- registry and local configuration;
- volatile token or credential material;
- hypervisor or network-device telemetry.

A negative MDI alert search does not clear these surfaces.

## Coverage checks

Before analysis record:

- table or API availability;
- first and last event time;
- ingestion health and delay;
- field population rates;
- retention horizon;
- license-dependent fields;
- schema or API version;
- known connector filtering;
- sampling, truncation, or result limits.

Use event timestamps for chronology. Keep ingestion and detection timestamps separately because offline detections may arrive later.

## Correlation cautions

- UPN and email are mutable labels; prefer stable object IDs within a provider.
- IP identifies a network observation, not a person or physical location.
- Correlation IDs may be client supplied or scoped to one authentication sequence.
- Device IDs can be absent, stale, cloned, or attacker-controlled.
- Cross-provider identity mapping is probabilistic unless an approved mapping table exists.
- Application-issued session cookies may hide subsequent activity from Entra.
