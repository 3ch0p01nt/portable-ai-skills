# Cisco Investigation Evidence, Timeline, and Confidence

Version 1.0.0 - 2026-08-28

## Unified evidence record

Every artifact and observation uses one record:

| Field | Required meaning |
|---|---|
| `artifact_id` | Stable identifier derived from the independently computed SHA-256 of the redacted analysis copy |
| `device_id` | Case-scoped pseudonym or approved identifier |
| `platform_family` | `ios`, `ios-xe`, `ios-xr`, `nx-os`, `asa`, `ftd`, `fmc`, `wlc`, `sd-wan`, `ise`, `catalyst-center`, `nso`, `cisco-rv`, or `unknown` |
| `platform_layer` | `boot`, `rommon`, `grub`, `fxos`, `kernel`, `lina`, `application`, `container`, `config`, `network`, `controller`, or `external` |
| `investigation_mode` | `live`, `dead-box`, `syslog-only`, `config-diff`, `fleet`, or `threat-intel` |
| `source_system` | Device, collector, AAA, controller, tap, repository, ticket, or analyst observation |
| `source_trust` | T0 untrusted device-local; T1 device-local corroborated; T2 external but mutable; T3 independent preserved; T4 authoritative forensic determination |
| `deception_risk` | `none-known`, `possible`, `documented`, or `unknown` with explanation |
| `collection_time_utc` | ISO 8601 UTC |
| `event_time_original` | Original timestamp exactly as observed |
| `event_time_utc` | Normalized ISO 8601 UTC or null |
| `timezone_confidence` | `confirmed-ntp`, `declared-offset`, `uptime-derived`, `local-naive`, or `unknown` |
| `collector_receive_time` | External receive time when available |
| `sequence_number` | Original sequence number or null |
| `volatile` | Boolean |
| `content_sha256` | Independently computed hash of the preserved original |
| `chain_of_custody` | Acquirer, method, witness/waiver, storage, write protection, and transfers |
| `can_prove` | Claims directly supported |
| `cannot_prove` | Explicit limits |
| `expected_corroboration` | Independent source that should agree |
| `observed_anomalies` | Structured finding IDs |
| `benign_explanations` | Candidate explanation plus supporting/refuting evidence |
| `confidence_contribution` | E0-E5 contribution |
| `next_action` | Safest action that can change confidence |

JSON validation uses `schemas/evidence.schema.json`.

## Evidence trust

| Tier | Meaning |
|---|---|
| T0 | Device-local output from a potentially compromised layer; never clearance |
| T1 | Device-local output corroborated by a distinct device layer |
| T2 | External operational source with incomplete custody or attacker reachability |
| T3 | Independently preserved external evidence with hash and custody |
| T4 | Cisco/CISA/NCSC/TAC or qualified forensic determination on acquired evidence |

Two outputs from the same compromised device are not independent.

## Three-axis conclusion model

### Evidence confidence

- E0 Unavailable: required evidence absent or inaccessible.
- E1 Speculative: hypothesis with no platform-specific artifact.
- E2 Low: one weak or ambiguous artifact.
- E3 Moderate: one strong platform-specific artifact or several weak independent artifacts.
- E4 High: multiple independent artifacts across different source systems/layers.
- E5 Confirmed: verified primary artifact/rule plus independent corroboration, or authoritative forensic determination.

### Compromise verdict

- Confirmed compromise: E5 and direct compromise evidence.
- Likely compromise: E4 with a coherent attack sequence.
- Suspicious: E2-E3; more evidence required.
- Likely benign: E3 or higher, all mandatory platform checks complete, each anomaly has a corroborated benign explanation, and no critical layer is untested.
- Undetermined: E0-E1, deceptive evidence, conflicting evidence, or a mandatory layer unavailable.

`Likely benign` is not `cleared`. It means current evidence does not support compromise within the tested layers.

### Actor alignment

- None: no actor-specific assessment.
- Possible: one actor-consistent behavior with matching platform.
- Plausible: multiple independent behaviors plus timing or victimology.
- Strong: E4-E5 evidence, multiple independent behaviors, timing, victimology, and no better competing explanation.

Actor alignment cannot exceed evidence confidence. Infrastructure overlap alone never establishes attribution.

## Hypothesis register

Each hypothesis contains:

- ID and statement.
- Platform/layer and predicted artifacts.
- Supporting evidence IDs.
- Contradicting evidence IDs.
- Benign alternatives.
- Untested predictions.
- Evidence confidence.
- Next evidence that would raise or lower confidence.
- Status: active, supported, weakened, rejected, or confirmed.

Missing expected evidence can be:

- Neutral absence: no collection existed.
- Evidence-quality finding: collection should exist but is missing.
- Positive anti-forensic behavior: a documented collection attempt caused suppression, reboot, falsified output, or other response.

## Timeline rules

1. Preserve original timestamp and normalized UTC separately.
2. Normalize all modes, not only syslog.
3. Record device clock, NTP peers/state, timezone, uptime, reload epoch, and collector time.
4. For uptime timestamps, calculate event UTC only when collection UTC and current uptime are known; label `uptime-derived`.
5. Do not treat `! Last configuration change at` as an exact command timestamp; it is a config-save marker.
6. Sequence gaps and volume gaps are separate findings.
7. A counter reset requires restart/failover/collector context.
8. Fleet timelines retain per-device skew and do not claim simultaneity inside the uncertainty interval.
9. Record analyst actions and their outcomes in the same timeline, including no-dump reboots.

## Chain-of-custody minimum

```text
Artifact ID:
Description:
Source device/system:
Platform/layer:
Acquirer:
Acquisition method:
Start/end time UTC:
Witness or waiver:
Original SHA-256:
Analysis-copy SHA-256:
Storage path:
Write-protection method:
Transfers:
Redactions/pseudonyms:
Notes:
```

Hash the original before analysis. An onboard `verify` result is not a custody hash.

## Artifact survivability

| Family/layer | Graceful reboot | Hard power loss | Write erase | Application upgrade | Reimage |
|---|---|---|---|---|---|
| LINE VIPER | Lost unless redeployed | Lost | Lost | Lost unless redeployed | Lost |
| RayInitiator GRUB bootkit | Survives | Survives | Survives | Documented to survive | Requires boot-chain remediation/TAC path |
| FIRESTARTER running process | Relaunches through staged persistence | Lost | Layer-dependent | Survives application update | Definitive platform reimage/remediation |
| LINE DANCER | Lost | Lost | Lost | Lost | Lost |
| LINE RUNNER on vulnerable branch | Survives/re-stages | Survives | May remove config but not necessarily all disk artifacts | Historically survived vulnerable upgrades | Removed by complete clean rebuild |
| BadCandy implant | Lost | Lost | Lost | Lost | Lost |
| BadCandy privileged account | Survives | Survives | Removed | May survive | Removed |
| SYNful Knock base image | Survives | Survives | Survives if image remains | Removed by verified clean image; ROMMON remains separate | Removed by verified clean image |
| Jaguar Tooth | Lost | Lost | Lost | Lost | Lost |
| JumbledPath process | Lost | Lost | Container/file dependent | Container/file dependent | Removed by clean rebuild |
| KV Botnet process | Lost | Lost | Lost | Lost | Lost; reinfection risk remains |

Always verify current vendor guidance before using this table for destructive action.

## Mandatory uncleared-layer statement

Every verdict lists each layer as tested, untested, unavailable, or untrusted:

- Memory/process.
- Boot/GRUB/ROMMON.
- FXOS/host.
- Disk/filesystem.
- Running/startup/config history.
- AAA/identity/PKI.
- Network/flow/PCAP.
- Orchestrator/controller.
- HA/peer.

No single negative result clears any other layer.
