"""Recursive local Cisco artifact folder analyzer.

This module never connects to devices, executes artifact content, fetches URLs,
or extracts archives to disk. It produces evidence-bounded findings and an
extensive coverage report, not a final compromise verdict.
"""

from __future__ import annotations

import argparse
import fnmatch
import gzip
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from cisco_artifact_parser import PARSER_VERSION, detect_artifact_type, parse_text


ROOT = Path(__file__).resolve().parents[1]
CLASSIFICATION_PATH = ROOT / "rules" / "artifact-classification-rules.json"
RUBRIC_PATH = ROOT / "rules" / "folder-rubric.json"
SCHEMA_VERSION = "1.0.0"
ANALYZER_VERSION = "1.1.0"
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


@dataclass(frozen=True)
class FolderOptions:
    run_id: str | None = None
    mode: str = "dead-box"
    source_trust: str = "T2"
    preview: bool = False
    include_archives: bool = True
    allow_unc: bool = False
    exclude_patterns: tuple[str, ...] = ()
    max_files: int = 100_000
    max_text_bytes: int = 5 * 1024 * 1024
    max_archive_bytes: int = 256 * 1024 * 1024
    max_archive_members: int = 5_000
    max_archive_depth: int = 3
    max_compression_ratio: float = 100.0
    max_member_name_bytes: int = 512


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _utc_from_timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _compound_extension(name: str) -> str:
    lowered = name.lower()
    for suffix in (
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
        ".tgz",
        ".tbz2",
        ".txz",
        ".pcapng",
    ):
        if lowered.endswith(suffix):
            return suffix
    return Path(lowered).suffix


def _looks_binary(data: bytes) -> bool:
    sample = data[:4096]
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    controls = sum(
        1 for byte in sample if byte < 9 or (13 < byte < 32)
    )
    return controls / len(sample) > 0.02


def _is_office_container(extension: str, data: bytes) -> bool:
    if extension in {".docx", ".xlsx", ".pptx"}:
        return True
    if not data.startswith(b"PK\x03\x04"):
        return False
    lowered = data.lower()
    return b"[content_types].xml" in lowered and any(
        marker in lowered for marker in (b"word/", b"xl/", b"ppt/")
    )


def classify_bytes(name: str, data: bytes) -> dict[str, Any]:
    rules = _load_json(CLASSIFICATION_PATH)
    lowered = name.lower()
    extension = _compound_extension(lowered)
    magic_kind = None
    artifact_type = "unknown"
    platform = "unknown"
    confidence = 0.0

    for magic in rules["magic"]:
        prefix = bytes.fromhex(magic["hex"])
        if data.startswith(prefix):
            magic_kind = magic["kind"]
            artifact_type = magic["artifact_type"]
            platform = magic["platform_family"]
            confidence = float(magic["confidence"])
            break

    if _is_office_container(extension, data):
        return {
            "artifact_type": "unknown",
            "platform_family": "unknown",
            "confidence": 1.0,
            "magic_kind": "office-open-xml",
            "extension": extension,
            "is_archive": False,
            "is_binary": True,
            "ambiguous": False,
        }

    archive = extension in rules["archive_extensions"] or magic_kind in {
        "zip",
        "gzip",
        "bzip2",
        "xz",
    }
    if archive:
        return {
            "artifact_type": "archive",
            "platform_family": "unknown",
            "confidence": max(confidence, 0.8),
            "magic_kind": magic_kind,
            "extension": extension,
            "is_archive": True,
            "is_binary": True,
            "ambiguous": False,
        }

    binary = _looks_binary(data) or extension in rules["binary_extensions"]
    if binary and artifact_type == "unknown":
        if extension in {".pcap", ".pcapng", ".cap"}:
            artifact_type = "pcap"
            confidence = max(confidence, 0.75)
        elif extension in {".core", ".dump"}:
            artifact_type = "core"
            confidence = max(confidence, 0.7)
    if binary:
        return {
            "artifact_type": artifact_type,
            "platform_family": platform,
            "confidence": confidence,
            "magic_kind": magic_kind,
            "extension": extension,
            "is_archive": False,
            "is_binary": True,
            "ambiguous": False,
        }

    text = data.decode("utf-8", errors="replace")
    artifact_type = detect_artifact_type(text)
    type_confidence = 0.0
    if artifact_type == "config":
        for marker in rules.get("artifact_markers", []):
            if re.search(marker["filename_pattern"], name) or re.search(
                marker["content_pattern"], text
            ):
                artifact_type = marker["artifact_type"]
                type_confidence = float(marker["confidence"])
                break

    candidates: list[tuple[float, str]] = []
    platform_subject = re.sub(r"[-_.]+", " ", name) + "\n" + text
    for marker in rules["platform_markers"]:
        if re.search(marker["pattern"], platform_subject):
            candidates.append(
                (float(marker["confidence"]), marker["platform_family"])
            )
    candidates.sort(reverse=True)
    ambiguous = False
    if candidates:
        platform = candidates[0][1]
        confidence = candidates[0][0]
        if len(candidates) > 1 and candidates[0][1] != candidates[1][1]:
            if candidates[0][0] - candidates[1][0] < float(
                rules["ambiguity_gap"]
            ):
                platform = "unknown"
                ambiguous = True
    return {
        "artifact_type": artifact_type,
        "platform_family": platform,
        "confidence": max(confidence, type_confidence),
        "magic_kind": magic_kind,
        "extension": extension,
        "is_archive": False,
        "is_binary": False,
        "ambiguous": ambiguous,
    }


def _is_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attrs = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attrs & REPARSE_POINT)
    except OSError:
        return False


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _validate_roots(
    input_root: Path,
    output_root: Path,
    options: FolderOptions,
) -> tuple[Path, Path]:
    if not input_root.is_absolute():
        raise ValueError("Input root must be an absolute path")
    if str(input_root).startswith("\\\\") and not options.allow_unc:
        raise ValueError("UNC input requires --allow-unc")
    root = input_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Input root must be a directory")
    out = output_root.resolve(strict=False)
    if out == root or _is_within(out, root):
        raise ValueError("Output root must be outside the input tree")
    return root, out


def _excluded(relative: str, patterns: tuple[str, ...]) -> bool:
    lowered = relative.lower()
    return any(fnmatch.fnmatch(lowered, pattern.lower()) for pattern in patterns)


def _flatten_manifest_items(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for item in items:
        flattened.append(item)
        flattened.extend(_flatten_manifest_items(item.get("members", [])))
    return flattened


def _discover(root: Path, options: FolderOptions) -> list[dict[str, Any]]:
    discovered: list[dict[str, Any]] = []
    file_count = 0
    for current, directories, filenames in os.walk(
        root, topdown=True, followlinks=False
    ):
        current_path = Path(current)
        safe_dirs: list[str] = []
        for directory in sorted(directories, key=str.lower):
            candidate = current_path / directory
            relative = candidate.relative_to(root).as_posix()
            if _is_reparse(candidate):
                discovered.append(
                    {
                        "path": candidate,
                        "relative_path": relative,
                        "is_reparse": True,
                        "is_directory": True,
                    }
                )
            elif not _excluded(relative, options.exclude_patterns):
                safe_dirs.append(directory)
        directories[:] = safe_dirs

        for filename in sorted(filenames, key=str.lower):
            path = current_path / filename
            relative = path.relative_to(root).as_posix()
            discovered.append(
                {
                    "path": path,
                    "relative_path": relative,
                    "is_reparse": _is_reparse(path),
                    "is_directory": False,
                    "excluded": _excluded(relative, options.exclude_patterns),
                }
            )
            file_count += 1
            if file_count > options.max_files:
                raise ValueError(
                    f"Discovered item count exceeds max_files={options.max_files}"
                )
    return sorted(
        discovered,
        key=lambda item: item["relative_path"].lower(),
    )


def _safe_member_name(name: str, options: FolderOptions) -> bool:
    if len(name.encode("utf-8", errors="replace")) > options.max_member_name_bytes:
        return False
    if any(char in name for char in ("\x00", "\u202e", "\u202d", "\u200f", "\u200e")):
        return False
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        return False
    if re.match(r"^[A-Za-z]:", normalized):
        return False
    if re.match(
        r"^(?:disk\d|bootflash|harddisk|flash|crashinfo|slot\d|nvram):",
        normalized,
        re.I,
    ):
        return False
    parts = PurePosixPath(normalized).parts
    return ".." not in parts and "." not in parts


def _read_stream_limited(
    stream: BinaryIO,
    member_limit: int,
    total_counter: list[int],
    total_limit: int,
) -> bytes:
    chunks: list[bytes] = []
    member_count = 0
    while True:
        chunk = stream.read(min(1024 * 1024, member_limit + 1 - member_count))
        if not chunk:
            break
        member_count += len(chunk)
        total_counter[0] += len(chunk)
        if member_count > member_limit or total_counter[0] > total_limit:
            raise ValueError("archive byte limit exceeded")
        chunks.append(chunk)
    return b"".join(chunks)


def _device_id(relative_path: str, text: str = "") -> tuple[str, str]:
    parts = PurePosixPath(relative_path).parts
    folder_hint = parts[0] if len(parts) > 1 else "root"
    serial_match = re.search(
        r"(?im)\b(?:Processor board ID|Chassis Serial Number|Serial Number)"
        r"\s*[:#]?\s*([A-Z0-9-]{6,})",
        text,
    )
    if serial_match:
        identity_key = f"serial|{serial_match.group(1).lower()}"
        pseudonym = hashlib.sha256(
            identity_key.encode("utf-8")
        ).hexdigest()[:10].upper()
        return f"DEV-{pseudonym}", "high"

    hostname_match = re.search(
        r"(?im)^\s*(?:hostname|switchname)\s+([A-Za-z0-9_.-]+)",
        text,
    )
    if not hostname_match:
        hostname_match = re.search(
            r"(?im)^.*\s([A-Za-z][A-Za-z0-9_.-]*)\s*:\s*%[A-Z0-9_]+-",
            text,
        )
    hostname = hostname_match.group(1) if hostname_match else ""
    if hostname and folder_hint == "root":
        identity_key = f"host|{hostname.lower()}"
    elif hostname:
        identity_key = f"{folder_hint.lower()}|host|{hostname.lower()}"
    else:
        identity_key = f"path|{relative_path.replace(chr(92), '/').lower()}"
    pseudonym = hashlib.sha256(identity_key.encode("utf-8")).hexdigest()[:10].upper()
    confidence = "medium" if hostname else "low"
    return f"DEV-{pseudonym}", confidence


def _duplicate_scope(relative_path: str) -> str:
    outer_path = relative_path.split("!", 1)[0]
    parts = PurePosixPath(outer_path).parts
    return parts[0].lower() if len(parts) > 1 else "root"


def _metadata_record(
    *,
    original_sha256: str,
    artifact_type: str,
    platform_family: str,
    platform_layer: str,
    mode: str,
    source_system: str,
    source_trust: str,
    collection_time_utc: str,
    device_id: str,
    payload: dict[str, Any],
    anomalies: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    anomalies = anomalies or []
    artifact_id = hashlib.sha256(
        f"{original_sha256}|{source_system}".encode("utf-8")
    ).hexdigest()
    return {
        "artifact_id": artifact_id,
        "artifact_type": (
            artifact_type
            if artifact_type
            in {
                "syslog",
                "show-tech",
                "config",
                "config-diff",
                "file-listing",
                "hash",
                "vpn-session",
                "aaa",
                "flow",
                "pcap",
                "core",
                "controller-export",
                "ticket",
                "analyst-observation",
                "unknown",
            }
            else "unknown"
        ),
        "device_id": device_id,
        "platform_family": platform_family,
        "platform_layer": platform_layer,
        "investigation_mode": mode,
        "source_system": source_system,
        "source_trust": source_trust,
        "deception_risk": {
            "level": "possible" if source_trust in {"T0", "T1"} else "unknown",
            "reason": "Metadata-only artifact; content not parsed",
        },
        "collection_time_utc": collection_time_utc,
        "event_time_original": None,
        "event_time_utc": None,
        "timezone_confidence": "unknown",
        "collector_receive_time": None,
        "sequence_number": None,
        "volatile": artifact_type in {"pcap", "core", "vpn-session"},
        "content_sha256": original_sha256,
        "chain_of_custody": None,
        "can_prove": ["The artifact existed with this hash and metadata"],
        "cannot_prove": [
            "Metadata-only handling does not establish artifact content or compromise",
            "Untested platform layers remain uncleared",
        ],
        "expected_corroboration": [],
        "observed_anomalies": anomalies,
        "benign_explanations": [],
        "confidence_contribution": "E2" if anomalies else "E1",
        "next_action": "Use an authorized specialist parser or forensic workflow",
        "payload": payload,
        "redaction_manifest": {
            "rules_fired": [],
            "redaction_count": 0,
            "residual_secret_lines": [],
        },
    }


def _name_anomalies(name: str) -> list[dict[str, Any]]:
    lowered = name.lower()
    candidates = [
        (
            "FILE-LINE-RUNNER-ZIP",
            r"client_bundle[\w-]*\.zip$",
            "filesystem",
            "Client-bundle ZIP requires LINE RUNNER branch review",
        ),
        (
            "FILE-FIRMWARE-UPDATE-LOG",
            r"firmware_update\.log$",
            "boot",
            "Cisco ROMMON remediation log requires preservation and TAC review",
        ),
        (
            "FILE-FIRESTARTER",
            r"(?:^|[\\/])lina_cs$|svc_samcore\.log$|CSP_MOUNT_LIST(?:\.tmp)?$",
            "filesystem",
            "FIRESTARTER-related path requires current-source review",
        ),
        (
            "FILE-BADCANDY",
            r"cisco_service\.conf$",
            "filesystem",
            "IOS XE Web UI implant path requires BadCandy branch review",
        ),
    ]
    return [
        {
            "id": finding_id,
            "category": category,
            "description": description,
            "line": None,
        }
        for finding_id, pattern, category, description in candidates
        if re.search(pattern, lowered, re.I)
    ]


def _finding_severity(flag_id: str, category: str) -> str:
    if flag_id in {"FILE-FIRESTARTER", "FILE-FIRMWARE-UPDATE-LOG"}:
        return "critical"
    if flag_id in {"FILE-LINE-RUNNER-ZIP", "FILE-BADCANDY"}:
        return "high"
    if category in {"identity", "persistence", "eem", "span", "loopback", "boot"}:
        return "high"
    if category in {"network-control", "management", "security"}:
        return "medium"
    return "low"


def _excerpt(record: dict[str, Any]) -> str:
    payload = record.get("payload", {})
    if "events" in payload:
        return "\n".join(
            event.get("raw_message", "") for event in payload["events"][:3]
        )[:500]
    for key in ("redacted_text", "redacted_diff", "redacted_listing"):
        if key in payload:
            return str(payload[key])[:500]
    return ""


def _render_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Cisco Artifact Folder Analysis",
        "",
        f"- Scan: `{report['scan_id']}`",
        f"- Analyzer: `{report['analyzer_version']}`",
        "- Components: "
        + ", ".join(
            f"{name}={version}"
            for name, version in sorted(report["component_versions"].items())
        ),
        f"- Generated UTC: `{report['generated_at_utc']}`",
        f"- Files discovered: **{summary['files_discovered']}**",
        f"- Evidence records: **{summary['evidence_records']}**",
        f"- Findings: **{summary['findings']}**",
        f"- Devices: **{summary['devices']}**",
        f"- Errors/skips: **{summary['errors_or_skips']}**",
        "",
        "## Automated assessment",
        "",
        (
            "**Attention required.** Evidence flags require investigator review."
            if report["findings"]
            else "**Review complete with no deterministic flags.** This is not clearance."
        ),
        "",
        "The analyzer does not issue a final compromise verdict or actor attribution.",
        "",
        "## Findings",
        "",
        "| Severity | Confidence | Device | Finding | Evidence |",
        "|---|---|---|---|---|",
    ]
    for finding in report["findings"]:
        lines.append(
            f"| {finding['severity']} | {finding['evidence_confidence']} | "
            f"{finding['device_id']} | {finding['title']} | "
            f"{', '.join(finding['evidence_ids'])} |"
        )
    if not report["findings"]:
        lines.append("| - | - | - | No deterministic finding | - |")

    lines.extend(
        [
            "",
            "## Per-device summary",
            "",
            "| Device | Identity confidence | Artifacts | Findings | Platforms |",
            "|---|---|---|---|---|",
        ]
    )
    for device in report["devices"]:
        lines.append(
            f"| {device['device_id']} | {device['identity_confidence']} | "
            f"{len(device['evidence_ids'])} | {len(device['finding_ids'])} | "
            f"{', '.join(device['platforms']) or 'unknown'} |"
        )

    lines.extend(
        [
            "",
            "## Extensive analysis rubric",
            "",
            "| Domain | Coverage | Artifacts | Missing evidence / next analysis |",
            "|---|---|---|---|",
        ]
    )
    for domain in report["rubric"]["domains"]:
        lines.append(
            f"| {domain['title']} | {domain['status']} | "
            f"{', '.join(domain['artifact_types_present']) or 'none'} | "
            f"{domain['missing_evidence']} |"
        )

    lines.extend(["", "## Detailed rubric checks", ""])
    for domain in report["rubric"]["domains"]:
        lines.extend(
            [
                f"### {domain['title']}",
                "",
                "| Check | Status | Evidence types present | Missing evidence |",
                "|---|---|---|---|",
            ]
        )
        for check in domain["checks"]:
            lines.append(
                f"| {check['title']} | {check['status']} | "
                f"{', '.join(check['artifact_types_present']) or 'none'} | "
                f"{check['missing_evidence']} |"
            )
        lines.append("")

    lines.extend(
        [
            "",
            "## Timeline",
            "",
            "| Event time UTC | Device | Evidence | Observation |",
            "|---|---|---|---|",
        ]
    )
    for event in report["timeline"][:200]:
        observation = event["observation"].replace("|", "\\|")
        lines.append(
            f"| {event.get('event_time_utc') or 'unknown'} | {event['device_id']} | "
            f"{event['evidence_id']} | {observation[:180]} |"
        )
    if len(report["timeline"]) > 200:
        lines.append(
            f"| - | - | - | {len(report['timeline']) - 200} additional events in timeline.json |"
        )

    lines.extend(["", "## Limitations", ""])
    for limitation in report["limitations"]:
        lines.append(f"- {limitation}")
    lines.extend(
        [
            "- Binary metadata-only records do not establish content.",
            "- Unsupported or unavailable layers remain uncleared.",
            "- A missing deterministic flag is not evidence that a device is clean.",
            "",
        ]
    )
    return "\n".join(lines)


def _rubric(evidence_summaries: list[dict[str, Any]]) -> dict[str, Any]:
    rules = _load_json(RUBRIC_PATH)
    present = {
        summary["artifact_type"] for summary in evidence_summaries
    }
    domains: list[dict[str, Any]] = []
    for domain in rules["domains"]:
        checks: list[dict[str, Any]] = []
        domain_present: set[str] = set()
        for check in domain["checks"]:
            required = set(check["artifact_types"])
            overlap = sorted(required & present)
            domain_present.update(overlap)
            checks.append(
                {
                    "id": check["id"],
                    "title": check["title"],
                    "status": "artifact-available" if overlap else "unavailable",
                    "artifact_types_present": overlap,
                    "missing_evidence": (
                        "Requires one of: " + ", ".join(sorted(required))
                        if not overlap
                        else "No artifact-type gap for this check"
                    ),
                }
            )
        covered_count = sum(
            1 for check in checks if check["status"] == "artifact-available"
        )
        if covered_count == 0:
            status = "unavailable"
        elif covered_count == len(checks):
            status = "artifact-available"
        else:
            status = "partial"
        missing_checks = [
            check["title"]
            for check in checks
            if check["status"] != "artifact-available"
        ]
        domains.append(
            {
                "id": domain["id"],
                "title": domain["title"],
                "status": status,
                "artifact_types_present": sorted(domain_present),
                "missing_evidence": (
                    f"{len(missing_checks)} checks lack matching artifact types"
                    if missing_checks
                    else "All rubric checks have matching artifact types"
                ),
                "checks": checks,
                "covered_checks": covered_count,
                "total_checks": len(checks),
            }
        )
    return {"version": rules["version"], "domains": domains}


def analyze_folder(
    input_root: Path,
    output_root: Path,
    options: FolderOptions | None = None,
) -> dict[str, Any]:
    options = options or FolderOptions()
    root, out = _validate_roots(input_root, output_root, options)
    discovered = _discover(root, options)
    run_id = options.run_id or "run-" + datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    run_dir = out / run_id
    if run_dir.exists():
        raise FileExistsError(f"Run directory already exists: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=False)

    manifest_items: list[dict[str, Any]] = []
    evidence_summaries: list[dict[str, Any]] = []
    findings_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    timeline: list[dict[str, Any]] = []
    devices: dict[str, dict[str, Any]] = {}
    seen_hashes: dict[tuple[str, str], str] = {}
    file_counter = [
        sum(1 for item in discovered if not item.get("is_directory"))
    ]
    evidence_path = run_dir / "evidence.jsonl"
    evidence_handle = None if options.preview else evidence_path.open(
        "w", encoding="utf-8", newline="\n"
    )

    def register_record(
        record: dict[str, Any],
        manifest_item: dict[str, Any],
    ) -> None:
        if evidence_handle is not None:
            evidence_handle.write(
                json.dumps(record, sort_keys=True, separators=(",", ":"))
                + "\n"
            )
        evidence_summaries.append(
            {
                "artifact_id": record["artifact_id"],
                "artifact_type": record["artifact_type"],
                "platform_family": record["platform_family"],
                "device_id": record["device_id"],
                "source_system": record["source_system"],
                "source_trust": record["source_trust"],
            }
        )
        manifest_item["evidence_id"] = record["artifact_id"]
        manifest_item["redacted_excerpt"] = _excerpt(record)
        device = devices.setdefault(
            record["device_id"],
            {
                "device_id": record["device_id"],
                "identity_confidence": manifest_item.get(
                    "device_identity_confidence", "low"
                ),
                "evidence_ids": [],
                "finding_ids": [],
                "platforms": set(),
            },
        )
        device["evidence_ids"].append(record["artifact_id"])
        if record["platform_family"] != "unknown":
            device["platforms"].add(record["platform_family"])

        for flag in record["observed_anomalies"]:
            key = (flag["id"], record["device_id"])
            finding = findings_by_key.setdefault(
                key,
                {
                    "finding_id": (
                        f"F-{flag['id']}-{record['device_id']}"
                    ),
                    "title": flag["description"],
                    "category": flag["category"],
                    "severity": _finding_severity(
                        flag["id"], flag["category"]
                    ),
                    "evidence_confidence": "E2",
                    "device_id": record["device_id"],
                    "platform_family": record["platform_family"],
                    "evidence_ids": [],
                    "source_systems": [],
                    "benign_alternatives": [],
                    "untested_layers": [
                        "memory/process",
                        "boot/ROMMON/GRUB",
                        "orchestrator/controller",
                    ],
                    "next_evidence": record["next_action"],
                },
            )
            if record["artifact_id"] not in finding["evidence_ids"]:
                finding["evidence_ids"].append(record["artifact_id"])
            if record["source_system"] not in finding["source_systems"]:
                finding["source_systems"].append(record["source_system"])

        if record["artifact_type"] == "syslog":
            for event in record.get("payload", {}).get("events", []):
                timeline.append(
                    {
                        "event_time_utc": record.get("event_time_utc"),
                        "device_id": record["device_id"],
                        "evidence_id": record["artifact_id"],
                        "line": event.get("line"),
                        "observation": event.get("raw_message", ""),
                        "time_confidence": record.get(
                            "timezone_confidence", "unknown"
                        ),
                    }
                )

    def process_bytes(
        *,
        data: bytes,
        virtual_path: str,
        original_sha256: str,
        modified_utc: str,
        manifest_item: dict[str, Any],
        size_bytes: int | None = None,
        archive_depth: int = 0,
        archive_counter: list[int] | None = None,
    ) -> None:
        size_bytes = len(data) if size_bytes is None else size_bytes
        classification = classify_bytes(virtual_path, data[:65536])
        manifest_item.update(classification)
        text = ""
        if not classification["is_binary"]:
            text = data.decode("utf-8", errors="replace")
        device_id, identity_confidence = _device_id(virtual_path, text)
        manifest_item["device_id"] = device_id
        manifest_item["device_identity_confidence"] = identity_confidence

        if options.preview:
            manifest_item["status"] = (
                "metadata-only"
                if classification["is_binary"]
                else "parsed"
            )
            return

        name_flags = _name_anomalies(virtual_path)
        if classification["is_archive"]:
            record = _metadata_record(
                original_sha256=original_sha256,
                artifact_type="unknown",
                platform_family="unknown",
                platform_layer="filesystem",
                mode=options.mode,
                source_system=f"folder:{virtual_path}",
                source_trust=options.source_trust,
                collection_time_utc=modified_utc,
                device_id=device_id,
                payload={
                    "relative_path": virtual_path,
                    "archive": True,
                    "size_bytes": size_bytes,
                },
                anomalies=name_flags,
            )
            register_record(record, manifest_item)
            manifest_item["status"] = "parsed"
            if options.include_archives:
                manifest_item["members"] = []
                _process_archive(
                    data=data,
                    name=virtual_path,
                    parent_item=manifest_item,
                    depth=archive_depth,
                    total_counter=archive_counter or [0],
                )
            else:
                manifest_item["status"] = "metadata-only"
            return

        if classification["is_binary"]:
            record = _metadata_record(
                original_sha256=original_sha256,
                artifact_type=classification["artifact_type"],
                platform_family=classification["platform_family"],
                platform_layer=(
                    "network"
                    if classification["artifact_type"] == "pcap"
                    else "unknown"
                ),
                mode=options.mode,
                source_system=f"folder:{virtual_path}",
                source_trust=options.source_trust,
                collection_time_utc=modified_utc,
                device_id=device_id,
                payload={
                    "relative_path": virtual_path,
                    "size_bytes": size_bytes,
                    "magic_kind": classification["magic_kind"],
                },
                anomalies=name_flags,
            )
            register_record(record, manifest_item)
            manifest_item["status"] = "metadata-only"
            return

        if len(data) > options.max_text_bytes:
            manifest_item["status"] = "skipped-oversize"
            manifest_item["error"] = (
                f"text bytes {len(data)} exceed {options.max_text_bytes}"
            )
            return

        artifact_type = classification["artifact_type"]
        record = parse_text(
            text,
            artifact_type=artifact_type,
            platform_family=classification["platform_family"],
            platform_layer=(
                "external"
                if artifact_type in {"syslog", "aaa", "flow"}
                else "config"
                if artifact_type in {"config", "config-diff"}
                else "unknown"
            ),
            investigation_mode=options.mode,
            source_system=f"folder:{virtual_path}",
            source_trust=options.source_trust,
            collection_time_utc=modified_utc,
            max_bytes=options.max_text_bytes,
        )
        record["device_id"] = device_id
        record["observed_anomalies"].extend(name_flags)
        register_record(record, manifest_item)
        manifest_item["status"] = "parsed"

    def _process_archive(
        *,
        data: bytes,
        name: str,
        parent_item: dict[str, Any],
        depth: int,
        total_counter: list[int],
    ) -> None:
        if depth >= options.max_archive_depth:
            parent_item["archive_error"] = "maximum archive depth reached"
            return
        members = parent_item.setdefault("members", [])
        member_count = 0

        def count_entry() -> None:
            nonlocal member_count
            member_count += 1
            file_counter[0] += 1
            if member_count > options.max_archive_members:
                raise ValueError("archive member count exceeded")
            if file_counter[0] > options.max_files:
                raise ValueError("max_files limit exceeded")

        def process_member(
            member_name: str,
            member_data: bytes,
        ) -> None:
            virtual = f"{name}!{member_name}"
            member_item: dict[str, Any] = {
                "relative_path": virtual,
                "virtual_path": virtual,
                "archive_parent": name,
                "size_bytes": len(member_data),
                "members": [],
            }
            members.append(member_item)
            digest = _sha256_bytes(member_data)
            duplicate_key = (digest, _duplicate_scope(virtual))
            if duplicate_key in seen_hashes:
                member_item["status"] = "duplicate"
                member_item["duplicate_of"] = seen_hashes[duplicate_key]
                member_item["original_sha256"] = digest
                return
            seen_hashes[duplicate_key] = virtual
            member_item["original_sha256"] = digest
            process_bytes(
                data=member_data,
                virtual_path=virtual,
                original_sha256=digest,
                modified_utc=parent_item["modified_utc"],
                manifest_item=member_item,
                archive_depth=depth + 1,
                archive_counter=total_counter,
            )

        try:
            kind = classify_bytes(name, data[:65536])["magic_kind"]
            extension = _compound_extension(name)
            if kind == "zip" or extension == ".zip":
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    for info in archive.infolist():
                        count_entry()
                        if info.is_dir():
                            continue
                        item = {
                            "relative_path": f"{name}!{info.filename}",
                            "virtual_path": f"{name}!{info.filename}",
                            "archive_parent": name,
                            "size_bytes": info.file_size,
                        }
                        if not _safe_member_name(info.filename, options):
                            item["status"] = "skipped-archive-path"
                            members.append(item)
                            continue
                        mode = (info.external_attr >> 16) & 0xFFFF
                        if stat.S_ISLNK(mode):
                            item["status"] = "skipped-reparse"
                            members.append(item)
                            continue
                        if info.flag_bits & 0x1:
                            item["status"] = "skipped-encrypted"
                            members.append(item)
                            continue
                        if (
                            info.compress_size > 0
                            and info.file_size / info.compress_size
                            > options.max_compression_ratio
                        ):
                            item["status"] = "skipped-archive-limit"
                            members.append(item)
                            continue
                        try:
                            with archive.open(info) as stream:
                                member_data = _read_stream_limited(
                                    stream,
                                    max(
                                        options.max_text_bytes,
                                        min(
                                            options.max_archive_bytes,
                                            info.file_size,
                                        ),
                                    ),
                                    total_counter,
                                    options.max_archive_bytes,
                                )
                            process_member(info.filename, member_data)
                        except ValueError as error:
                            item["status"] = "skipped-archive-limit"
                            item["error"] = str(error)
                            members.append(item)
                            raise
            elif extension in {
                ".tar",
                ".tar.gz",
                ".tgz",
                ".tar.bz2",
                ".tbz2",
                ".tar.xz",
                ".txz",
            }:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                    for info in archive:
                        count_entry()
                        if not info.isfile():
                            if info.issym() or info.islnk():
                                members.append(
                                    {
                                        "relative_path": f"{name}!{info.name}",
                                        "virtual_path": f"{name}!{info.name}",
                                        "status": "skipped-reparse",
                                    }
                                )
                            continue
                        if not _safe_member_name(info.name, options):
                            members.append(
                                {
                                    "relative_path": f"{name}!{info.name}",
                                    "virtual_path": f"{name}!{info.name}",
                                    "status": "skipped-archive-path",
                                }
                            )
                            continue
                        stream = archive.extractfile(info)
                        if stream is None:
                            continue
                        try:
                            member_data = _read_stream_limited(
                                stream,
                                max(
                                    options.max_text_bytes,
                                    min(options.max_archive_bytes, info.size),
                                ),
                                total_counter,
                                options.max_archive_bytes,
                            )
                            process_member(info.name, member_data)
                        except ValueError as error:
                            members.append(
                                {
                                    "relative_path": f"{name}!{info.name}",
                                    "virtual_path": f"{name}!{info.name}",
                                    "status": "skipped-archive-limit",
                                    "error": str(error),
                                }
                            )
                            raise
            elif kind == "gzip" or extension == ".gz":
                count_entry()
                member_name = Path(name).name[:-3] or "gzip-member"
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                    member_data = _read_stream_limited(
                        stream,
                        options.max_archive_bytes,
                        total_counter,
                        options.max_archive_bytes,
                    )
                process_member(member_name, member_data)
            else:
                parent_item["archive_error"] = "unsupported archive format"
        except (OSError, EOFError, zipfile.BadZipFile, tarfile.TarError, ValueError) as error:
            parent_item["archive_error"] = str(error)

    try:
        for discovered_item in discovered:
            relative = discovered_item["relative_path"]
            item: dict[str, Any] = {
                "relative_path": relative,
                "members": [],
            }
            manifest_items.append(item)
            path = discovered_item["path"]

            if discovered_item.get("is_directory"):
                item["status"] = "skipped-reparse"
                item["kind"] = "directory"
                continue
            if discovered_item.get("is_reparse"):
                item["status"] = "skipped-reparse"
                continue
            if discovered_item.get("excluded"):
                item["status"] = "excluded-user"
                continue
            try:
                size = path.stat().st_size
                modified_utc = _utc_from_timestamp(path.stat().st_mtime)
                item["size_bytes"] = size
                item["modified_utc"] = modified_utc
                digest = _sha256_file(path)
                item["original_sha256"] = digest
                duplicate_key = (digest, _duplicate_scope(relative))
                if duplicate_key in seen_hashes:
                    item["status"] = "duplicate"
                    item["duplicate_of"] = seen_hashes[duplicate_key]
                    continue
                seen_hashes[duplicate_key] = relative
                with path.open("rb") as handle:
                    header = handle.read(65536)
                classification = classify_bytes(relative, header)
                item.update(classification)
                if (
                    not classification["is_binary"]
                    and size > options.max_text_bytes
                ):
                    item["status"] = "skipped-oversize"
                    item["error"] = (
                        f"text bytes {size} exceed {options.max_text_bytes}"
                    )
                    continue
                if classification["is_archive"] and size > options.max_archive_bytes:
                    item["status"] = "skipped-archive-limit"
                    item["error"] = (
                        f"archive bytes {size} exceed {options.max_archive_bytes}"
                    )
                    continue
                if options.preview:
                    process_bytes(
                        data=header,
                        virtual_path=relative,
                        original_sha256=digest,
                        modified_utc=modified_utc,
                        manifest_item=item,
                        size_bytes=size,
                    )
                    continue
                if (
                    classification["is_binary"]
                    and not classification["is_archive"]
                ):
                    process_bytes(
                        data=header,
                        virtual_path=relative,
                        original_sha256=digest,
                        modified_utc=modified_utc,
                        manifest_item=item,
                        size_bytes=size,
                    )
                else:
                    data = path.read_bytes()
                    process_bytes(
                        data=data,
                        virtual_path=relative,
                        original_sha256=digest,
                        modified_utc=modified_utc,
                        manifest_item=item,
                        size_bytes=size,
                    )
            except (OSError, UnicodeError, ValueError) as error:
                item["status"] = "parse-error"
                item["error"] = str(error)
    finally:
        if evidence_handle is not None:
            evidence_handle.close()

    findings = list(findings_by_key.values())
    for finding in findings:
        finding["source_independence_count"] = 0
        device = devices[finding["device_id"]]
        device["finding_ids"].append(finding["finding_id"])
    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }
    findings.sort(
        key=lambda finding: (
            severity_order.get(finding["severity"], 4),
            finding["device_id"],
            finding["finding_id"],
        )
    )
    timeline.sort(
        key=lambda event: (
            event.get("event_time_utc") or "",
            event["device_id"],
            event["evidence_id"],
            event.get("line") or 0,
        )
    )
    device_list = []
    for device in sorted(devices.values(), key=lambda value: value["device_id"]):
        device_list.append(
            {
                **device,
                "platforms": sorted(device["platforms"]),
                "finding_ids": sorted(set(device["finding_ids"])),
            }
        )

    all_manifest_items = _flatten_manifest_items(manifest_items)
    skips = sum(
        1
        for item in all_manifest_items
        if item.get("status")
        not in {"parsed", "metadata-only", "duplicate"}
    )
    rubric = _rubric(evidence_summaries)
    limitations = [
        f"{item['relative_path']}: {item.get('status')} {item.get('error', '')}".strip()
        for item in all_manifest_items
        if item.get("status")
        not in {"parsed", "metadata-only", "duplicate"}
    ]
    generated = _now_utc()
    component_versions = {
        "evidence_schema": _load_json(
            ROOT / "schemas" / "evidence.schema.json"
        )["version"],
        "folder_report_schema": _load_json(
            ROOT / "schemas" / "folder-report.schema.json"
        )["version"],
        "classification_rules": _load_json(CLASSIFICATION_PATH)["version"],
        "rubric_rules": _load_json(RUBRIC_PATH)["version"],
        "artifact_parser": PARSER_VERSION,
    }
    scan_id = hashlib.sha256(
        f"{root}|{run_id}".encode("utf-8")
    ).hexdigest()[:16]
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "analyzer_version": ANALYZER_VERSION,
        "component_versions": component_versions,
        "scan_id": scan_id,
        "analyzer_version": ANALYZER_VERSION,
        "component_versions": component_versions,
        "generated_at_utc": generated,
        "input_root": str(root),
        "output_dir": str(run_dir),
        "options": asdict(options),
        "summary": {
            "files_discovered": len(
                [item for item in discovered if not item.get("is_directory")]
            ),
            "evidence_records": len(evidence_summaries),
            "findings": len(findings),
            "devices": len(device_list),
            "duplicates": sum(
                1 for item in all_manifest_items if item.get("status") == "duplicate"
            ),
            "errors_or_skips": skips,
        },
        "manifest": {"artifacts": manifest_items},
        "devices": device_list,
        "findings": findings,
        "timeline": timeline,
        "rubric": rubric,
        "limitations": limitations,
    }

    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "scan_id": scan_id,
                "generated_at_utc": generated,
                "input_root": str(root),
                "options": asdict(options),
                "summary": report["summary"],
                "artifacts": manifest_items,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    if not options.preview:
        (run_dir / "findings.json").write_text(
            json.dumps(findings, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (run_dir / "timeline.json").write_text(
            json.dumps(timeline, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (run_dir / "report.md").write_text(
            _render_report(report),
            encoding="utf-8",
        )
        devices_dir = run_dir / "devices"
        devices_dir.mkdir()
        for device in device_list:
            device_findings = [
                finding
                for finding in findings
                if finding["device_id"] == device["device_id"]
            ]
            lines = [
                f"# Device {device['device_id']}",
                "",
                f"- Identity confidence: {device['identity_confidence']}",
                f"- Platforms: {', '.join(device['platforms']) or 'unknown'}",
                f"- Evidence records: {len(device['evidence_ids'])}",
                f"- Findings: {len(device_findings)}",
                "",
                "## Findings",
                "",
            ]
            for finding in device_findings:
                lines.append(
                    f"- **{finding['severity']} / {finding['evidence_confidence']}** "
                    f"{finding['title']} (`{finding['finding_id']}`)"
                )
            lines.extend(
                [
                    "",
                    "## Uncleared layers",
                    "",
                    "- Memory/process",
                    "- Boot/ROMMON/GRUB",
                    "- FXOS/host where applicable",
                    "- Controller/orchestrator",
                    "",
                ]
            )
            (devices_dir / f"{device['device_id']}.md").write_text(
                "\n".join(lines),
                encoding="utf-8",
            )
    return report


def _cli() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a local folder of Cisco artifacts"
    )
    parser.add_argument("input_root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--mode",
        choices=(
            "live",
            "dead-box",
            "syslog-only",
            "config-diff",
            "fleet",
            "threat-intel",
        ),
        default="dead-box",
    )
    parser.add_argument(
        "--source-trust",
        choices=("T0", "T1", "T2", "T3", "T4"),
        default="T2",
    )
    parser.add_argument("--preview", action="store_true")
    parser.add_argument("--no-archives", action="store_true")
    parser.add_argument("--allow-unc", action="store_true")
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--max-files", type=int, default=100_000)
    parser.add_argument("--max-text-bytes", type=int, default=5 * 1024 * 1024)
    parser.add_argument(
        "--max-archive-bytes",
        type=int,
        default=256 * 1024 * 1024,
    )
    parser.add_argument("--max-members", type=int, default=5_000)
    parser.add_argument("--max-archive-depth", type=int, default=3)
    parser.add_argument("--max-compression-ratio", type=float, default=100.0)
    args = parser.parse_args()

    input_root = args.input_root
    if not input_root.is_absolute():
        parser.error("input_root must be absolute")
    output = args.output or input_root.parent / (
        input_root.name + "-cisco-analysis"
    )
    options = FolderOptions(
        mode=args.mode,
        source_trust=args.source_trust,
        preview=args.preview,
        include_archives=not args.no_archives,
        allow_unc=args.allow_unc,
        exclude_patterns=tuple(args.exclude),
        max_files=args.max_files,
        max_text_bytes=args.max_text_bytes,
        max_archive_bytes=args.max_archive_bytes,
        max_archive_members=args.max_members,
        max_archive_depth=args.max_archive_depth,
        max_compression_ratio=args.max_compression_ratio,
    )
    report = analyze_folder(input_root, output, options)
    print(
        json.dumps(
            {
                "scan_id": report["scan_id"],
                "output_dir": report["output_dir"],
                "summary": report["summary"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
