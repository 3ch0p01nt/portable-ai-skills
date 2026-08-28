#!/usr/bin/env python3
"""Online freshness checker for the Cisco skill source manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path


MANUAL_EXPIRY_DAYS = 30
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/140.0 Safari/537.36 "
    "portable-ai-skills-source-check/1.1"
)


def bundle_root(value: str | None = None) -> Path:
    return (
        Path(value).expanduser().resolve()
        if value
        else Path(__file__).resolve().parents[1]
    )


def fetch_url(url: str, timeout: int) -> tuple[int, bytes, str]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/json,application/pdf,*/*",
            "Accept-Language": "en-US,en;q=0.9",
        },
        method="GET",
    )
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(
            request, timeout=timeout, context=context
        ) as response:
            return response.status, response.read(), response.geturl()
    except (OSError, urllib.error.URLError) as original_error:
        curl = shutil.which("curl")
        if not curl:
            raise
        completed = subprocess.run(
            [
                curl,
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--max-time",
                str(timeout),
                "--user-agent",
                USER_AGENT,
                "--header",
                "Accept: text/html,application/xhtml+xml,application/json,application/pdf,*/*",
                "--header",
                "Accept-Language: en-US,en;q=0.9",
                url,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout + 5,
        )
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise OSError(f"{original_error}; curl fallback failed: {detail}")
        return 200, completed.stdout, url


def manual_status(source: dict, today: date) -> tuple[str, str] | None:
    value = source.get("manual_verified_on")
    if not value:
        return None
    try:
        verified = date.fromisoformat(value)
    except ValueError:
        return "review_required", f"invalid manual verification date: {value}"
    age = (today - verified).days
    method = source.get("manual_verification_method", "documented review")
    if 0 <= age <= MANUAL_EXPIRY_DAYS:
        return "manual_ok", f"manually verified {value} by {method}; age {age} days"
    return "review_required", f"manual verification is stale ({age} days)"


def check_source(source: dict, root: Path, timeout: int, today: date) -> dict:
    source_id = source.get("id", "<unknown>")
    kind = source.get("kind", "uncategorized")
    if source.get("path"):
        path = root / source["path"]
        return {
            "id": source_id,
            "category": kind,
            "location": source["path"],
            "status": "ok" if path.is_file() else "missing",
            "detail": "local source",
        }

    result = {
        "id": source_id,
        "category": kind,
        "location": source.get("url"),
        "status": "review_required",
        "detail": "",
        "observed_sha256": None,
        "expected_sha256": source.get("expected_sha256"),
        "version_matched": None,
    }
    errors = []
    urls = [source.get("url"), source.get("fallback_url")]
    for candidate in (url for url in urls if url):
        try:
            status_code, content, final_url = fetch_url(candidate, timeout)
            if not 200 <= status_code < 400:
                raise OSError(f"HTTP {status_code}")
            is_fallback = candidate != source.get("url")
            suffix = "; fallback used" if is_fallback else ""
            expected_hash = (
                source.get("fallback_expected_sha256")
                if is_fallback and "fallback_expected_sha256" in source
                else source.get("expected_sha256")
            )
            expected_version = (
                source.get("fallback_version_label")
                if is_fallback and "fallback_version_label" in source
                else source.get("version_label")
            )
            if expected_hash:
                observed = hashlib.sha256(content).hexdigest().upper()
                result["observed_sha256"] = observed
                result["expected_sha256"] = expected_hash
                if observed != expected_hash.upper():
                    result["detail"] = f"content hash changed{suffix}"
                    continue
                result["detail"] = f"content hash matched{suffix}"
            elif expected_version:
                label = str(expected_version).encode()
                matched = label in content
                result["version_matched"] = matched
                if not matched:
                    result["detail"] = f"recorded version not found{suffix}"
                    continue
                result["detail"] = f"authoritative source reachable{suffix}"
            else:
                result["detail"] = f"HTTP {status_code}{suffix}"
            result["status"] = "ok"
            result["resolved_url"] = final_url
            return result
        except Exception as exc:  # source failures become status records
            errors.append(f"{candidate}: {exc}")

    fallback = manual_status(source, today)
    if fallback:
        result["status"], manual_detail = fallback
        prefix = "automated retrieval inconclusive; " if errors else ""
        result["detail"] = prefix + manual_detail
    elif errors:
        result["detail"] = "; ".join(errors)
    elif not result["detail"]:
        result["detail"] = "no reachable source URL"
    return result


def check_manifest(
    manifest: dict,
    root: Path | str,
    timeout: int = 20,
    output_path: Path | str | None = None,
    today: date | None = None,
    workers: int = 8,
) -> dict:
    root = Path(root).resolve()
    today = today or date.today()
    sources = manifest.get("sources", [])
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        results = list(
            executor.map(
                lambda source: check_source(source, root, timeout, today), sources
            )
        )
    review = [
        result
        for result in results
        if result["status"] not in {"ok", "manual_ok"}
    ]
    summary = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        "ok": sum(result["status"] == "ok" for result in results),
        "manual_ok": sum(result["status"] == "manual_ok" for result in results),
        "review_required": len(review),
        "categories": {
            kind: sum(result["category"] == kind for result in results)
            for kind in sorted({result["category"] for result in results})
        },
        "results": results,
    }
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", help="Cisco skill bundle root")
    parser.add_argument("--timeout", type=int, default=20, help="Per-request timeout")
    parser.add_argument("--strict", action="store_true", help="Fail on unresolved sources")
    parser.add_argument("--output", help="Write the JSON summary to this path")
    parser.add_argument("--workers", type=int, default=8, help="Concurrent source checks")
    args = parser.parse_args(argv)
    root = bundle_root(args.root)
    try:
        manifest = json.loads(
            (root / "references/sources.json").read_text(encoding="utf-8")
        )
        summary = check_manifest(
            manifest,
            root,
            timeout=args.timeout,
            output_path=args.output,
            workers=args.workers,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(summary, indent=2))
    return int(args.strict and summary["review_required"] > 0)


if __name__ == "__main__":
    sys.exit(main())
