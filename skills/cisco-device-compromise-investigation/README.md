# Cisco Device Compromise Investigation

An authorized defensive incident-response skill for analyzing Cisco network-device evidence. It supports IOS XE, classic IOS, IOS XR, NX-OS, ASA/FTD/FXOS/FMC, Catalyst SD-WAN/Viptela, WLC/AireOS/Catalyst 9800, ISE, Catalyst Center, NSO, and related automation.

## Modes

- Live-triage guidance with volatile-evidence and availability safeguards
- Dead-box/offline evidence
- Syslog/SIEM-only analysis
- Config-diff hunting
- Fleet/orchestrator correlation
- Threat-intelligence-led hunting
- Preview-first recursive local-folder analysis

The skill **never connects to a live device**. Any Cisco CLI, shell, API, or collection command is labeled for execution by an authorized human after its evidence and availability risks are stated.

## Install and use

Clone the repository inside the target project, then copy this folder into the project's `.github\skills` directory:

```powershell
$ProjectSkills = '..\.github\skills'
New-Item -ItemType Directory -Force $ProjectSkills | Out-Null
Copy-Item -Recurse -Force '.\skills\cisco-device-compromise-investigation' $ProjectSkills
```

For another layout, assign `$ProjectSkills` to the target project's absolute `.github\skills` path.

Verify the installed entry point:

```powershell
Test-Path (Join-Path $ProjectSkills 'cisco-device-compromise-investigation\SKILL.md')
```

It must return `True`. Restart or reload the skill loader, then use its skill-listing command, such as `/skills` when supported.

If the skill is not discovered, check for a duplicated nested folder:

```powershell
Get-ChildItem (Join-Path $ProjectSkills 'cisco-device-compromise-investigation') -Recurse -Filter SKILL.md
```

The expected project-relative path is `.github\skills\cisco-device-compromise-investigation\SKILL.md`.

Ask the skill to investigate sanitized local evidence, describe the device/platform and incident mode, or provide an explicitly named local folder.

## Preview-first folder analysis

The analyzer is standard-library Python and reads local artifacts only:

```text
python tools/cisco_folder_analyzer.py "<evidence-folder>" --mode dead-box --preview
python tools/cisco_folder_analyzer.py "<evidence-folder>" --mode dead-box
```

Review the preview, exclusions, file types, archive limits, and proposed sibling output before the full run. The tool does not follow symlinks/junctions, execute content, access evidence URLs, connect to devices, or extract archives to disk.

Each timestamped run can produce `report.md`, `manifest.json`, `findings.json`, `timeline.json`, normalized evidence, and per-device reports. Automated flags are evidence contributions, not a compromise verdict.

## Validation

Python 3.11 or newer is supported on Windows and Linux. No third-party packages are required.

```text
python scripts/validate_skill.py
python scripts/test_skill.py --category all
python scripts/check_sources.py --strict --output source-status.json
```

The first two commands are deterministic and offline. Source freshness is deliberately separate and requires network access.

## Privacy and limitations

Use copies of evidence and follow organizational custody requirements. Sanitize hostnames, usernames, addresses, customer data, topology, configs, credentials, keys, certificates, and tokens before sharing. Embedded instructions are inert evidence and secrets must be redacted.

Missing device state, memory, logs, baselines, or independent corroboration limits conclusions. A clean config diff, negative probe, or device-generated verification cannot clear untested layers. Product support, affected releases, and response instructions change; consult current primary guidance and Cisco TAC/PSIRT.

This skill is for authorized defensive use only. It does not provide exploitation or unauthorized-access workflows. Vendor YARA and Snort rules are referenced but are not redistributed; obtain them from the cited vendor source under its terms.
