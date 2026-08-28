"""Local-only Cisco artifact parser.

The parser redacts common secrets, normalizes a small set of artifact formats,
and emits deterministic evidence flags. It never executes artifact content,
makes network requests, or produces a compromise verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PARSER_VERSION = "1.2.0"
REDACTION_RULES = ROOT / "rules" / "redaction-rules.json"
CONFIG_RULES = ROOT / "rules" / "config-diff-rules.json"
DEFAULT_MAX_BYTES = 5 * 1024 * 1024


@lru_cache(maxsize=4)
def _load_rules(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["rules"]


def _snmpv3_secret_remains(line: str) -> bool:
    tokens = line.split()
    lowered = [token.lower() for token in tokens]
    if len(tokens) < 6 or lowered[:2] != ["snmp-server", "user"] or "v3" not in lowered:
        return False
    if "auth" in lowered:
        index = lowered.index("auth")
        if index + 2 >= len(tokens) or tokens[index + 2] != "[REDACTED]":
            return True
    if "priv" in lowered:
        index = lowered.index("priv")
        secret_index = index + 2
        if secret_index < len(tokens) and tokens[secret_index] in {"128", "192", "256"}:
            secret_index += 1
        if secret_index >= len(tokens) or tokens[secret_index] != "[REDACTED]":
            return True
    return False


def redact_text(text: str) -> tuple[str, dict[str, Any]]:
    redacted = text
    fired: list[str] = []
    count = 0
    for rule in _load_rules(REDACTION_RULES):
        redacted, substitutions = re.subn(
            rule["pattern"],
            rule["replacement"],
            redacted,
        )
        if substitutions:
            fired.append(rule["id"])
            count += substitutions
    residual_pattern = re.compile(
        r"(?i)\b(?:password|secret|community|pre-shared-key|"
        r"(?:tacacs|radius)-server\s+key|message-digest-key\s+\d+\s+md5|"
        r"key-string|authentication-key)"
        r"\b(?![^\r\n]*\[REDACTED\])"
    )
    residual_lines: list[int] = []
    safe_lines: list[str] = []
    for number, line in enumerate(redacted.splitlines(keepends=True), start=1):
        is_residual = _snmpv3_secret_remains(line) or (
            residual_pattern.search(line)
            and not re.search(r"(?i)^\s*key\s+(?:chain|config-key)\b", line)
        )
        if is_residual:
            residual_lines.append(number)
            ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            indent = re.match(r"^\s*", line).group(0)
            safe_lines.append(f"{indent}[REDACTION-REVIEW-REQUIRED]{ending}")
        else:
            safe_lines.append(line)
    redacted = "".join(safe_lines)
    return redacted, {
        "rules_fired": fired,
        "redaction_count": count,
        "residual_secret_lines": residual_lines,
    }


def pseudonymize_identifier(value: str, salt: str) -> str:
    digest = hmac.new(
        salt.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"[ID:{digest[:12]}]"


def detect_artifact_type(text: str) -> str:
    if "show tech-support" in text.lower():
        return "show-tech"
    if re.search(r"%ASA-\d-\d+:", text) or re.search(
        r"%[A-Z0-9_]+-\d-[A-Z0-9_]+:", text
    ):
        return "syslog"
    if re.search(r"(?m)^[+-](?![+-])\s*\S", text):
        return "config-diff"
    if "Directory of " in text:
        return "file-listing"
    if re.search(r"(?i)\b(?:md5|sha256|sha512|verified)\b", text):
        return "hash"
    return "config"


def _syslog_events(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    asa = re.compile(r"%(?P<facility>ASA)-(?P<severity>\d)-(?P<id>\d+):\s*(?P<body>.*)")
    ios = re.compile(
        r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<id>[A-Z0-9_]+):\s*(?P<body>.*)"
    )
    connection = re.compile(r"\bconnection\s+(?P<connection_id>\d+)\b", re.I)
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = asa.search(line) or ios.search(line)
        if not match:
            continue
        conn_match = connection.search(match.group("body"))
        events.append(
            {
                "line": line_number,
                "facility": match.group("facility"),
                "severity": int(match.group("severity")),
                "message_id": match.group("id"),
                "connection_id": (
                    conn_match.group("connection_id") if conn_match else None
                ),
                "raw_message": line,
            }
        )
    return events


def _config_diff_flags(text: str) -> list[dict[str, Any]]:
    flags: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    rules = _load_rules(CONFIG_RULES)
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in rules:
            if re.search(rule["pattern"], line):
                key = (rule["id"], line_number)
                if key in seen:
                    continue
                seen.add(key)
                flags.append(
                    {
                        "id": rule["id"],
                        "category": rule["category"],
                        "description": rule.get(
                            "description",
                            f"Config-diff rule matched at line {line_number}",
                        ),
                        "line": line_number,
                    }
                )
    return flags


def _file_flags(text: str) -> list[dict[str, Any]]:
    candidates = [
        (
            "FILE-LINE-RUNNER-ZIP",
            "filesystem",
            re.compile(r"client_bundle[\w-]*\.zip", re.I),
            "Client-bundle ZIP requires LINE RUNNER branch review",
        ),
        (
            "FILE-FIRMWARE-UPDATE-LOG",
            "boot",
            re.compile(r"firmware_update\.log", re.I),
            "Cisco ROMMON remediation log requires preservation and TAC review",
        ),
        (
            "FILE-FIRESTARTER",
            "filesystem",
            re.compile(r"(?:^|[\\/])lina_cs\b|svc_samcore\.log|CSP_MOUNT_LIST", re.I),
            "FIRESTARTER-related filename/path requires source-current review",
        ),
        (
            "FILE-BADCANDY",
            "filesystem",
            re.compile(r"cisco_service\.conf", re.I),
            "IOS XE Web UI implant path requires BadCandy branch review",
        ),
    ]
    flags: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule_id, category, pattern, description in candidates:
            if pattern.search(line):
                flags.append(
                    {
                        "id": rule_id,
                        "category": category,
                        "description": description,
                        "line": line_number,
                    }
                )
    return flags


def parse_text(
    text: str,
    *,
    artifact_type: str | None = None,
    platform_family: str = "unknown",
    platform_layer: str = "unknown",
    investigation_mode: str = "dead-box",
    source_system: str = "user-supplied",
    source_trust: str = "T0",
    collection_time_utc: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    encoded = text.encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError(f"Input exceeds max_bytes={max_bytes}")

    artifact_type = artifact_type or detect_artifact_type(text)
    if collection_time_utc is None:
        raise ValueError(
            "collection_time_utc is required for deterministic library output"
        )
    redacted, manifest = redact_text(text)
    original_sha256 = hashlib.sha256(encoded).hexdigest()
    artifact_id = hashlib.sha256(redacted.encode("utf-8")).hexdigest()

    flags: list[dict[str, Any]] = []
    payload: dict[str, Any] = {"redacted_text": redacted}
    confidence = "E1"
    deception_level = "possible" if source_trust in {"T0", "T1"} else "none-known"
    deception_reason = (
        "Device-local or incompletely corroborated evidence"
        if source_trust in {"T0", "T1"}
        else "Independent source; integrity still requires custody validation"
    )

    if manifest["residual_secret_lines"]:
        flags.append(
            {
                "id": "REDACTION-RESIDUAL-SECRET",
                "category": "security",
                "description": (
                    "One or more lines matched a secret heuristic after known-rule "
                    "redaction and were replaced for manual review"
                ),
                "line": manifest["residual_secret_lines"][0],
            }
        )

    if artifact_type == "syslog":
        payload = {"events": _syslog_events(redacted)}
    elif artifact_type == "config-diff":
        flags.extend(_config_diff_flags(redacted))
        payload = {"redacted_diff": redacted}
        if flags:
            confidence = "E2"
    elif artifact_type == "file-listing":
        flags.extend(_file_flags(redacted))
        payload = {"redacted_listing": redacted}
        if flags:
            confidence = "E2"
    elif artifact_type == "hash" and source_trust in {"T0", "T1"}:
        flags.append(
            {
                "id": "EVIDENCE-ONBOARD-HASH",
                "category": "evidence-quality",
                "description": (
                    "Onboard hash is not independent clearance when device compromise "
                    "or output deception is possible"
                ),
                "line": 1,
            }
        )

    return {
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "device_id": None,
        "platform_family": platform_family,
        "platform_layer": platform_layer,
        "investigation_mode": investigation_mode,
        "source_system": source_system,
        "source_trust": source_trust,
        "deception_risk": {
            "level": deception_level,
            "reason": deception_reason,
        },
        "collection_time_utc": collection_time_utc,
        "event_time_original": None,
        "event_time_utc": None,
        "timezone_confidence": "unknown",
        "collector_receive_time": None,
        "sequence_number": None,
        "volatile": artifact_type in {"syslog", "vpn-session", "core"},
        "content_sha256": original_sha256,
        "chain_of_custody": None,
        "can_prove": [],
        "cannot_prove": [
            "A parser flag is not a compromise verdict",
            "Untested platform layers remain uncleared",
        ],
        "expected_corroboration": [],
        "observed_anomalies": flags,
        "benign_explanations": [],
        "confidence_contribution": confidence,
        "next_action": "Review flags and obtain independent corroboration",
        "payload": payload,
        "redaction_manifest": manifest,
    }


def _cli() -> int:
    parser = argparse.ArgumentParser(description="Parse Cisco artifacts locally")
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--artifact-type")
    parser.add_argument("--platform-family", default="unknown")
    parser.add_argument("--platform-layer", default="unknown")
    parser.add_argument("--investigation-mode", default="dead-box")
    parser.add_argument("--source-system", default="local-file")
    parser.add_argument("--source-trust", default="T0")
    parser.add_argument("--collection-time-utc")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    args = parser.parse_args()

    for path in args.paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        collection_time_utc = args.collection_time_utc or datetime.fromtimestamp(
            path.stat().st_mtime,
            timezone.utc,
        ).isoformat().replace("+00:00", "Z")
        record = parse_text(
            text,
            artifact_type=args.artifact_type,
            platform_family=args.platform_family,
            platform_layer=args.platform_layer,
            investigation_mode=args.investigation_mode,
            source_system=args.source_system,
            source_trust=args.source_trust,
            collection_time_utc=collection_time_utc,
            max_bytes=args.max_bytes,
        )
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
