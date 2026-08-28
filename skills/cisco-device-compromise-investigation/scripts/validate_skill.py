#!/usr/bin/env python3
"""Deterministic, offline validation for the Cisco investigation skill."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


EXPECTED_EVALS = 72
EXPECTED_P0 = 41
EXPECTED_SOURCES = 45
MAX_SKILL_BYTES = 18_432

REQUIRED_FILES = (
    "SKILL.md",
    "README.md",
    "references/platform-artifacts.md",
    "references/threat-routing.md",
    "references/line-viper-rayinitiator.md",
    "references/cisco-malware-catalog.md",
    "references/forensic-safety.md",
    "references/evidence-schema.md",
    "references/detection-engineering.md",
    "references/output-templates.md",
    "references/folder-analysis.md",
    "references/sources.json",
    "schemas/evidence.schema.json",
    "schemas/folder-report.schema.json",
    "evals/evals.json",
    "rules/redaction-rules.json",
    "rules/config-diff-rules.json",
    "rules/artifact-classification-rules.json",
    "rules/folder-rubric.json",
    "tools/cisco_artifact_parser.py",
    "tools/cisco_folder_analyzer.py",
)

REQUIRED_EVALS = (
    "safety-live-fast-path",
    "safety-fceb-firestarter-stop",
    "safety-human-command-only",
    "safety-untrusted-orchestrator",
    "line-viper-direct-deployment",
    "syslog-no-baseline",
    "sdwan-ed26",
    "sdwan-cve-2022-20775-boundary",
    "salt-iosxr-57722",
    "salt-proxy-uri-benign-marker",
    "salt-iosxe-tacacs-epc",
    "cve-2025-20363-platform-scope",
    "freshness-authoritative-fallback",
    "badcandy-psirt-boundary",
    "jaguar-tooth-platform-boundary",
    "integrity-assurance-blind-spots",
    "freshness-source-gone",
    "folder-preview-first",
    "folder-output-boundary",
    "folder-archive-traversal",
    "folder-archive-bomb",
    "folder-secret-and-injection",
    "folder-no-flags-not-clean",
)


class ValidationError(RuntimeError):
    pass


def bundle_root(value: str | None = None) -> Path:
    return (
        Path(value).expanduser().resolve()
        if value
        else Path(__file__).resolve().parents[1]
    )


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"Invalid JSON {path}: {exc}") from exc


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def valid_https(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def validate_bundle(root: Path | str) -> dict:
    root = Path(root).resolve()
    for relative in REQUIRED_FILES:
        require((root / relative).is_file(), f"Missing required file: {relative}")

    skill_path = root / "SKILL.md"
    skill_bytes = skill_path.stat().st_size
    skill = skill_path.read_text(encoding="utf-8")
    match = re.match(r"^---\r?\n(.*?)\r?\n---", skill, re.DOTALL)
    require(match is not None, "SKILL.md frontmatter is missing or malformed")
    require("name:" in match.group(1), "SKILL.md frontmatter missing name")
    require("description:" in match.group(1), "SKILL.md frontmatter missing description")
    require(skill_bytes <= MAX_SKILL_BYTES, "SKILL.md exceeds 18,432 bytes")
    require(
        not re.search(r"(?m)^\s*-\s*(ssh|exec|run_command)\s*$", skill),
        "Unsafe live-device tool declared",
    )

    evals = load_json(root / "evals/evals.json")
    sources = load_json(root / "references/sources.json")
    evidence_schema = load_json(root / "schemas/evidence.schema.json")
    folder_schema = load_json(root / "schemas/folder-report.schema.json")
    redactions = load_json(root / "rules/redaction-rules.json")
    config_rules = load_json(root / "rules/config-diff-rules.json")
    classifications = load_json(root / "rules/artifact-classification-rules.json")
    folder_rubric = load_json(root / "rules/folder-rubric.json")

    cases = evals.get("cases", [])
    source_records = sources.get("sources", [])
    case_ids = [case.get("id") for case in cases]
    source_ids = [source.get("id") for source in source_records]
    require(len(cases) == EXPECTED_EVALS, f"Expected {EXPECTED_EVALS} evaluations")
    require(
        sum(case.get("priority") == "P0" for case in cases) == EXPECTED_P0,
        f"Expected {EXPECTED_P0} P0 evaluations",
    )
    require(len(source_records) == EXPECTED_SOURCES, f"Expected {EXPECTED_SOURCES} sources")
    require(len(case_ids) == len(set(case_ids)), "Duplicate evaluation IDs found")
    require(len(source_ids) == len(set(source_ids)), "Duplicate source IDs found")

    source_id_set = set(source_ids)
    used_sources: set[str] = set()
    for source in source_records:
        source_id = source.get("id", "<unknown>")
        if source.get("url"):
            require(valid_https(source["url"]), f"Invalid source URL: {source_id}")
            if source.get("fallback_url"):
                require(
                    valid_https(source["fallback_url"]),
                    f"Invalid fallback source URL: {source_id}",
                )
        elif source.get("path"):
            require((root / source["path"]).is_file(), f"Missing local source: {source_id}")
        else:
            raise ValidationError(f"Source lacks url or path: {source_id}")

    required_case_fields = (
        "id",
        "category",
        "priority",
        "mode",
        "platform",
        "source_ids",
        "input",
        "expected",
        "fail_if",
    )
    for case in cases:
        case_id = case.get("id", "<unknown>")
        for field in required_case_fields:
            require(field in case, f"Evaluation {case_id} missing {field}")
        require(bool(case["source_ids"]), f"Evaluation {case_id} has no source binding")
        require(bool(case["expected"]), f"Evaluation {case_id} has no expected behavior")
        require(bool(case["fail_if"]), f"Evaluation {case_id} has no failure condition")
        for source_id in case["source_ids"]:
            require(
                source_id in source_id_set,
                f"Evaluation {case_id} references unknown source {source_id}",
            )
            used_sources.add(source_id)

    for case_id in REQUIRED_EVALS:
        require(case_id in case_ids, f"Missing P0 evaluation: {case_id}")

    for field in (
        "artifact_id",
        "platform_family",
        "platform_layer",
        "investigation_mode",
        "source_trust",
        "deception_risk",
        "content_sha256",
        "confidence_contribution",
    ):
        require(
            field in evidence_schema.get("properties", {}),
            f"Evidence schema missing {field}",
        )

    require(len(redactions.get("rules", [])) >= 6, "Insufficient redaction rules")
    require(len(config_rules.get("rules", [])) >= 8, "Insufficient config-diff rules")
    require(len(classifications.get("magic", [])) >= 8, "Insufficient classifications")
    domains = folder_rubric.get("domains", [])
    require(len(domains) == 18, "Folder rubric must contain 18 domains")
    rubric_checks = sum(len(domain.get("checks", [])) for domain in domains)
    require(rubric_checks >= 80, "Folder rubric must contain at least 80 checks")
    require("rubric" in folder_schema.get("properties", {}), "Folder schema lacks rubric")

    unused_sources = sorted(source_id_set - used_sources)
    require(not unused_sources, f"Unused source records: {', '.join(unused_sources)}")

    return {
        "status": "PASS",
        "bundle_root": str(root),
        "skill_bytes": skill_bytes,
        "eval_cases": len(cases),
        "p0_cases": sum(case.get("priority") == "P0" for case in cases),
        "source_records": len(source_records),
        "unused_source_records": len(unused_sources),
        "redaction_rules": len(redactions["rules"]),
        "config_rules": len(config_rules["rules"]),
        "folder_rubric_domains": len(domains),
        "folder_rubric_checks": rubric_checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", help="Cisco skill bundle root")
    args = parser.parse_args(argv)
    try:
        summary = validate_bundle(bundle_root(args.root))
    except ValidationError as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
