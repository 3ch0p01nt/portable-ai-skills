# Example Style Guide

## Portable Detection Wrapper

Use this format for examples that teach complete detections:

```markdown
# Detection Title

## Query Information

### Category

Threat Hunting

### MITRE ATT&CK Techniques

| Technique ID | Title | Link |
|---|---|---|
| T1021.001 | Remote Desktop Protocol | https://attack.mitre.org/techniques/T1021/001/ |

### Description

Explain what the query detects and what security decision it supports.

### Risk

Explain why the behavior matters and what evidence increases or decreases confidence.

### False Positives

List common benign causes and tuning options.

### Blind Spots

List telemetry gaps, connector dependencies, and known ways the query can miss activity.

### Response Actions

List safe investigation steps.

### References

Link to public documentation or original source inspiration.

### Version History

| Version | Date | Impact | Notes |
|---|---|---|---|
| 1.0 | 2026-06-18 | initial | Initial portable example. |

## Defender XDR

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
```

## Sentinel

```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
```
```

## Attribution Rules

- Summarize and generalize public examples instead of copying large rule bodies.
- Keep short snippets only when they teach structure or syntax.
- Link to source inspiration when known.
- State platform assumptions and connector requirements.
- Include false positives, blind spots, and response actions for detection examples.
