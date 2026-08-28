# Cisco Artifact Folder Analysis

Version 1.1.0 - 2026-08-28

## Purpose

Analyze a local folder of Cisco device artifacts without modifying evidence, executing artifact content, contacting live devices, or making network requests.

The analyzer produces evidence records, correlated findings, coverage gaps, an extensive investigation rubric, and local reports. Automated output never declares a device clean and never establishes actor attribution.

## Command

```powershell
python tools\cisco_folder_analyzer.py <artifact-folder> `
  --output <sibling-output-root> `
  --mode dead-box
```

Options:

- `--preview`: discovery/classification manifest only.
- `--output`: output root; must not be inside the evidence folder.
- `--mode`: `live`, `dead-box`, `syslog-only`, `config-diff`, `fleet`, or `threat-intel`.
- `--source-trust`: default `T2`; use the evidence schema.
- `--exclude`: repeatable case-insensitive glob.
- `--max-files`: default 100000; counts outer files plus every encountered archive entry, including directories, links, encrypted members, and rejected names.
- `--max-text-bytes`: default 5242880.
- `--max-archive-bytes`: default 268435456 total streamed bytes per archive.
- `--max-members`: default 5000 per archive.
- `--max-archive-depth`: default 3.
- `--allow-unc`: disabled by default.
- `--no-archives`: catalog archives without reading members.

## Safety contract

1. Input root must be an existing absolute local directory.
2. UNC paths require `--allow-unc`.
3. Output must be outside the input tree and uses a new timestamped run directory.
4. The analyzer never overwrites a prior run.
5. It skips symlinks, junctions, and other reparse points.
6. It never executes files, imports artifact code, opens URLs, or invokes external parsers.
7. It does not extract archive members to disk. Supported members are streamed through bounded readers.
8. It hashes the original file before parsing.
9. Redaction occurs before text is written to output.
10. Unsupported, unreadable, oversized, encrypted, or malformed files remain in the manifest as evidence gaps.

## Supported inputs

### Text

- Cisco syslog and logging buffers.
- `show tech-support` and command bundles represented as text.
- Running/startup/committed configurations.
- Unified/Cisco config diffs.
- Flash/disk/bootflash file listings.
- Hash/checksum output.
- AAA/TACACS/RADIUS exports.
- VPN session exports.
- NetFlow/IPFIX CSV or text summaries.
- FMC, Catalyst Center, vManage, ISE, NSO, RANCID/Oxidized, Git, and automation exports in text/JSON/XML/CSV.

### Binary metadata only

- PCAP/PCAPNG.
- ELF/core dumps.
- IOS/ASA/NX-OS/IOS XR images/packages.
- PDF, Office, and image files.
- Unknown binaries.

Binary files are hashed and classified from extension/magic bytes; payload content is not parsed. DOCX, XLSX, and PPTX extensions, plus ZIP containers with Office Open XML structure, are classified as binary metadata before generic archive handling and are never traversed as evidence archives.

### Archives

Supported:

- ZIP.
- TAR.
- TAR.GZ/TGZ.
- GZIP single-member streams.
- TAR.BZ2/TBZ2.
- TAR.XZ/TXZ.

Unsupported formats are hashed and recorded without extraction.

Archive guardrails:

- Maximum nesting: 3.
- Maximum members per archive: 5000.
- Maximum streamed uncompressed bytes per archive: 256 MiB.
- Maximum compression ratio: 100:1 when sizes are known.
- Maximum member name: 512 UTF-8 bytes.
- Reject absolute, drive-qualified, UNC, Cisco-device-qualified, traversal, NUL, and bidirectional-control names.
- Reject links and device/special members.
- Encrypted members are recorded as `skipped-encrypted`.
- Nested members are represented as `archive.zip!path/member.txt`.
- Every ZIP/TAR directory, link, encrypted member, unsafe name, and supported file counts toward both `--max-members` and the global `--max-files` budget before validation or reading.
- Exceeding member, global file, or streamed-byte limits stops the current archive immediately; no later entries in that archive are inspected. Processing may continue with the next outer artifact.

## Discovery manifest

Every in-scope file receives:

- Relative path.
- Canonical path.
- Original SHA-256.
- Size and modification time.
- Extension and magic type.
- Artifact-type candidates with confidence.
- Platform candidates with confidence.
- Device identity candidate and confidence.
- Status.
- Duplicate-of reference.
- Archive/member provenance.
- Error or skip reason.

Unidentified artifacts receive distinct path-derived device pseudonyms. Artifacts merge only with a positive serial correlation or a scoped hostname correlation; a shared root fallback never merges unrelated files.

Statuses:

- `parsed`
- `metadata-only`
- `duplicate`
- `excluded-user`
- `skipped-reparse`
- `skipped-binary`
- `skipped-oversize`
- `skipped-encrypted`
- `skipped-archive-limit`
- `unsupported`
- `unreadable`
- `parse-error`

No file disappears silently.

## Classification

Classification uses:

1. Magic bytes.
2. Compound extension.
3. Filename/path hints.
4. Explicit AAA, VPN-session, NetFlow/IPFIX, and controller-audit filename/content markers.
5. First 64 KiB of decoded text.
6. Existing `detect_artifact_type`.

Artifact type and platform are resolved independently. Strong structural types such as config diff, show-tech, syslog, file listing, and hash output take precedence over export hints; controller export hints can still retain vManage, FMC, or Catalyst Center platform identity. AAA export hints require export-oriented filenames or structured AAA fields and do not override normal running configurations.

High-confidence magic:

- PCAP little/big endian and PCAPNG.
- ELF.
- ZIP.
- GZIP.
- BZIP2.
- XZ.
- PDF.
- PNG/JPEG.

Platform markers:

- ASA: `ASA Version`, `%ASA-`.
- FTD/FMC: `Firepower Threat Defense`, `FMC`, deployment/audit fields.
- IOS XE: `Cisco IOS XE`, `version 16`, `version 17`, platform/QFP/IOx markers.
- Classic IOS: `Cisco IOS Software`, version 12/15 without XE markers.
- IOS XR: `IOS XR`, `!! IOS XR Configuration`, route-policy/prefix-set.
- NX-OS: `NX-OS`, `!Command: show running-config`, Nexus/vPC features.
- SD-WAN: vManage/vSmart/vBond/Viptela control events.
- ISE: Cisco ISE application/audit/RADIUS/TACACS markers.
- WLC: AireOS, Catalyst 9800 wireless/AP/CAPWAP markers.
- Catalyst Center: DNA Center/Catalyst Center inventory/template/SWIM markers.
- NSO: NSO/NCS commit, NED, service, authgroup, NETCONF transaction markers.
- Cisco RV: RV model/config/XML markers.

If the two highest candidates are within 0.15, classification is ambiguous and remains `unknown` unless the user provides an override.

## Device identity and correlation

Candidate identity sources:

- Explicit manifest mapping.
- Chassis/serial reference.
- Hostname/device name.
- Management IP.
- Folder hierarchy.
- Controller inventory ID.

Precedence:

1. Matching serial/chassis IDs.
2. Explicit user mapping.
3. Matching hostname plus platform/model.
4. Management IP plus matching time window.
5. Folder-name hint only.

Never merge records on IP alone when DHCP, NAT, HA, or address reuse is plausible.

HA peers remain separate devices with a relationship edge.

Duplicates:

- Same original SHA-256: exact duplicate; one canonical record.
- Same redacted SHA-256 but different original hash: privacy-equivalent, not exact duplicate.
- Same event in multiple sources: separate evidence records linked by a correlation edge.

Independent evidence requires different source systems or trust boundaries. Two files exported from one compromised device are not independent.

## Finding model

Each finding includes:

- Finding ID and title.
- Device/fleet scope.
- Category and severity.
- Evidence confidence E0-E5.
- Evidence record IDs.
- Source-system independence count.
- Platform/layer.
- Observation.
- Threat/malware alignment when supported.
- Benign alternatives.
- Contradicting evidence.
- Untested/deceptive layers.
- Recommended next evidence.
- Response owner/authority.
- Source IDs and dates.

Severity and evidence confidence are separate.

Automated ceiling:

- One parser/rule hit: E2.
- Multiple corroborating files from the same source system remain E2.
- The analyzer does not automatically assert source independence and never promotes above E2.
- E3-E5 requires skill/human synthesis that verifies separate trust boundaries, timeline coherence, or an authoritative forensic determination.

The analyzer emits `attention_required`, `review`, or `informational`; it does not emit a final compromise verdict.

## Extensive analysis rubric

The case report evaluates all domains:

1. Scope, authorization, mode, and source freshness.
2. Evidence inventory, hashes, custody, duplicates, and gaps.
3. Device identity, platform, model, version, HA, clock/NTP, uptime/reload.
4. Local users, privilege, SSH keys, AAA method lists, TACACS/RADIUS, dormant accounts, MFA.
5. Management-plane exposure and access controls.
6. Configuration baselines, risky deltas, archives, EEM/kron, logging/NTP.
7. Runtime sessions, processes, sockets/listeners, CPU/memory, containers/GuestShell.
8. Filesystem artifacts, unexpected scripts/packages, crash/core/support bundles.
9. Image/package/boot/ROMMON/GRUB/FXOS/Secure Boot/Trust Anchor integrity.
10. Routing/control plane: ARP/MAC, BGP/OSPF/EIGRP/ISIS/MPLS/LDP, loopbacks, ACL/NAT, tunnels.
11. VPN, WebVPN, certificates/trustpoints, PKI, IKE/IPsec.
12. Packet capture, SPAN/ERSPAN, NetFlow/IPFIX, PCAP/NDR, DNS/proxy/firewall.
13. Malware-specific branches: LINE VIPER, RayInitiator, FIRESTARTER, LINE DANCER/RUNNER, BadCandy, SYNful Knock, Jaguar Tooth, JumbledPath, BlackTech, Velvet Ant, ZuoRAT, KV Botnet.
14. Persistence and reinfection paths.
15. Defense evasion and anti-forensics.
16. Controller/orchestrator changes and fleet blast radius.
17. Crown jewels, reachability, credential exposure, and business impact.
18. Hypotheses, benign explanations, verdict ceiling, response readiness, and next evidence.

Each domain reports:

- `artifact-available`, `partial`, `unavailable`, or `not-applicable`.
- Artifacts examined.
- Findings.
- Missing evidence.
- Confidence ceiling.
- Recommended next evidence.

`artifact-available` means one or more artifact types capable of addressing the check were parsed. It does not mean the check was substantively completed. Only the final skill synthesis may promote a check to covered after reviewing content and corroboration.

## Output structure

Default sibling:

```text
<input-name>-cisco-analysis\
  run-<UTC timestamp>\
    manifest.json
    evidence.jsonl
    findings.json
    timeline.json
    report.md
    devices\
      <device-pseudonym>.md
```

`manifest.json`: full discovery, limits, statuses, hashes, duplicates, errors.

`evidence.jsonl`: redacted evidence records.

`findings.json`: deduplicated finding register.

`timeline.json`: normalized events and uncertainty.

`report.md`: executive summary, scope, inventory, extensive rubric, findings, per-device status, timeline, malware/TTP alignment, crown jewels, gaps, recommended next evidence, and limitations.

Per-device reports: identity, artifact inventory, findings, rubric coverage, untested layers, and next actions.

## Report rules

- No raw secret value.
- No raw artifact content beyond short redacted evidence excerpts.
- No final `clean` statement.
- No unsupported actor attribution.
- Every finding cites evidence IDs.
- Every missing/failed file appears in limitations.
- Every report records analyzer/rule/schema version and original hashes.
- Existing outputs are never overwritten.

## Partial failure

A file error does not stop the run unless:

- Input root cannot be validated.
- Output would be inside input.
- File count exceeds the configured limit.
- Archive total exceeds the configured safety limit.
- The report cannot be written without overwrite.

Individual file/member errors are recorded and processing continues, except that an archive member-count, global file-count, or streamed-byte limit stops the remainder of that archive.

## Performance and determinism

- Walk in case-insensitive sorted relative-path order.
- Hash files in 1 MiB chunks.
- Read no more than 64 KiB for classification.
- Parse text only after stat/size/binary gates.
- Stream JSONL; do not retain redacted text for all files in memory.
- Cache by original SHA-256 plus parser/rules/schema version.
- Cache failure is a miss, never a correctness failure.
- Deterministic findings sort: severity, confidence, device, finding ID, evidence IDs.

## Acceptance

- Input tree is unchanged byte-for-byte.
- Output is outside input and contains no overwrite.
- Every in-scope file has a manifest status.
- Archives cannot escape or exhaust configured limits.
- Secrets and injection text never control analysis or leak.
- Exact duplicates do not inflate confidence.
- Ambiguous identity does not merge devices.
- Every finding cites evidence.
- All 18 rubric domains appear.
- Unsupported evidence lowers coverage instead of producing a clean result.
