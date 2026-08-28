#!/usr/bin/env python3
"""Run the Cisco skill's deterministic offline test categories."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from validate_skill import ValidationError, bundle_root, validate_bundle


CATEGORIES = ("correctness", "safety", "evidence", "detection", "parser", "folder", "all")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def read(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def test_correctness(root: Path) -> None:
    line_viper = read(root, "references/line-viper-rayinitiator.md")
    catalog = read(root, "references/cisco-malware-catalog.md")
    for phrase in (
        "Branch A: RayInitiator to LINE VIPER",
        "Branch B: direct LINE VIPER then FIRESTARTER",
    ):
        require(phrase in line_viper, f"Missing correctness rule: {phrase}")
    for phrase in (
        "the implant preserves image size",
        "Classic IOS confirmed",
        "RV320/RV325/RV420",
        "In-memory Volt Typhoon/JDY proxy implant",
    ):
        require(phrase in catalog, f"Missing correctness rule: {phrase}")


def scan_security(root: Path) -> None:
    patterns = {
        "persona-identity-override": re.compile(
            r"\b(you are now|pretend you are|forget you are|your new identity|your real purpose)\b",
            re.IGNORECASE,
        ),
        "mcp-tool-escalation": re.compile(
            r"mcp__[a-zA-Z_]+__(shell|execute|run_command|eval|exec)"
        ),
        "embedded-live-credential": re.compile(
            r"^\s*(?:password|secret|community|pre-shared-key)\s+[^\[<\s]\S+",
            re.IGNORECASE | re.MULTILINE,
        ),
    }
    files = [root / "SKILL.md", *sorted((root / "references").glob("*.md"))]
    for path in files:
        text = path.read_text(encoding="utf-8")
        for rule, pattern in patterns.items():
            require(not pattern.search(text), f"Security scan {rule}: {path.name}")


def test_safety(root: Path, eval_ids: set[str]) -> None:
    for case_id in (
        "safety-live-fast-path",
        "safety-fceb-firestarter-stop",
        "safety-human-command-only",
        "safety-untrusted-orchestrator",
        "safety-ha-reidentify",
        "safety-line-viper-delayed-reboot",
        "safety-rma-hold",
        "security-inert-evidence-redaction",
    ):
        require(case_id in eval_ids, f"Missing safety evaluation: {case_id}")
    skill = read(root, "SKILL.md")
    require("First-response safety router" in skill, "Fast safety router missing")
    require(
        "Never use a tool to connect to, authenticate to, or issue commands on a live Cisco device"
        in skill,
        "Human-only command rule missing",
    )
    scan_security(root)


def test_evidence(root: Path, eval_ids: set[str]) -> None:
    schema = json.loads(read(root, "schemas/evidence.schema.json"))
    for field in (
        "artifact_id",
        "platform_layer",
        "source_trust",
        "deception_risk",
        "content_sha256",
    ):
        require(field in schema["properties"], f"Evidence schema missing {field}")
    require("evidence-likely-benign-gate" in eval_ids, "Likely-benign gate missing")
    require("output-tac-package" in eval_ids, "TAC output evaluation missing")


def test_detection(root: Path, eval_ids: set[str]) -> None:
    for relative in (
        "detections/templates/splunk-spl.yaml",
        "detections/templates/sentinel-kql.yaml",
        "detections/templates/sigma-like.yaml",
        "detections/templates/config-compliance.yaml",
        "detections/templates/yara-runbook.md",
    ):
        require((root / relative).is_file(), f"Missing detection template: {relative}")
    for case_id in (
        "syslog-no-baseline",
        "syslog-collector-loss",
        "syslog-severity-seven",
        "sdwan-ed26",
        "iosxr-tpacap",
        "iosxe-epc",
    ):
        require(case_id in eval_ids, f"Missing detection evaluation: {case_id}")
    run_unittest(root, "test_detection_templates.py")


def run_unittest(root: Path, pattern: str) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            str(root / "tests"),
            "-p",
            pattern,
        ],
        cwd=root,
        check=False,
    )
    require(result.returncode == 0, f"Tests failed: {pattern}")


def test_folder(root: Path, eval_ids: set[str]) -> None:
    for relative in (
        "references/folder-analysis.md",
        "schemas/folder-report.schema.json",
        "rules/artifact-classification-rules.json",
        "rules/folder-rubric.json",
        "tools/cisco_folder_analyzer.py",
        "tests/test_cisco_folder_analyzer.py",
    ):
        require((root / relative).is_file(), f"Missing folder file: {relative}")
    for case_id in (
        "folder-preview-first",
        "folder-output-boundary",
        "folder-reparse-safety",
        "folder-archive-traversal",
        "folder-archive-bomb",
        "folder-binary-metadata",
        "folder-secret-and-injection",
        "folder-duplicate-confidence",
        "folder-device-correlation",
        "folder-partial-failure",
        "folder-extensive-rubric",
        "folder-findings-evidence",
        "folder-no-flags-not-clean",
        "folder-cross-source-timeline",
        "folder-report-set",
    ):
        require(case_id in eval_ids, f"Missing folder evaluation: {case_id}")


def run_tests(root: Path | str, category: str = "all") -> dict:
    root = Path(root).resolve()
    category = category.lower()
    require(category in CATEGORIES, f"Unknown category: {category}")
    validation = validate_bundle(root)
    evals = json.loads(read(root, "evals/evals.json"))
    eval_ids = {case["id"] for case in evals["cases"]}

    if category in {"correctness", "all"}:
        test_correctness(root)
    if category in {"safety", "all"}:
        test_safety(root, eval_ids)
    if category in {"evidence", "all"}:
        test_evidence(root, eval_ids)
    if category in {"detection", "all"}:
        test_detection(root, eval_ids)
    if category in {"parser", "all"}:
        run_unittest(root, "test_cisco_artifact_parser.py")
    if category in {"folder", "all"}:
        test_folder(root, eval_ids)
        run_unittest(root, "test_cisco_folder_analyzer.py")

    return {
        "status": "PASS",
        "category": category,
        "eval_cases": validation["eval_cases"],
        "p0_cases": validation["p0_cases"],
        "source_records": validation["source_records"],
        "unused_source_records": validation["unused_source_records"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", help="Cisco skill bundle root")
    parser.add_argument("--category", choices=CATEGORIES, default="all")
    args = parser.parse_args(argv)
    try:
        summary = run_tests(bundle_root(args.root), args.category)
    except (OSError, ValueError, json.JSONDecodeError, ValidationError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
