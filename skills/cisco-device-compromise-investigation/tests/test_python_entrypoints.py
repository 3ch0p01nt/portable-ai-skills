import importlib.util
import json
import tempfile
import unittest
import urllib.error
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


BUNDLE_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = BUNDLE_ROOT / "scripts"


def load_script(name):
    path = SCRIPTS / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ValidateSkillTests(unittest.TestCase):
    def test_offline_validation_preserves_quality_gates(self):
        module = load_script("validate_skill.py")
        summary = module.validate_bundle(BUNDLE_ROOT)
        self.assertEqual("PASS", summary["status"])
        self.assertEqual(72, summary["eval_cases"])
        self.assertEqual(41, summary["p0_cases"])
        self.assertEqual(45, summary["source_records"])
        self.assertEqual(0, summary["unused_source_records"])


class CheckSourcesTests(unittest.TestCase):
    def test_fetch_uses_cross_platform_curl_fallback_for_waf_block(self):
        module = load_script("check_sources.py")
        url = "https://www.cisa.gov/example"
        blocked = urllib.error.HTTPError(url, 403, "Forbidden", {}, None)
        completed = SimpleNamespace(
            returncode=0, stdout=b"official source", stderr=b""
        )
        with (
            mock.patch.object(module.urllib.request, "urlopen", side_effect=blocked),
            mock.patch.object(module.shutil, "which", return_value="curl"),
            mock.patch.object(module.subprocess, "run", return_value=completed) as run,
        ):
            status, content, resolved = module.fetch_url(url, 1)
        self.assertEqual((200, b"official source", url), (status, content, resolved))
        run.assert_called_once()

    def test_fallback_and_json_output(self):
        module = load_script("check_sources.py")
        manifest = {
            "sources": [
                {
                    "id": "fallback-source",
                    "url": "https://primary.invalid/source",
                    "fallback_url": "https://fallback.example/source",
                }
            ]
        }

        def fake_fetch(url, timeout):
            if "primary.invalid" in url:
                raise OSError("blocked")
            return 200, b"authoritative source", url

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "status.json"
            with mock.patch.object(module, "fetch_url", side_effect=fake_fetch):
                summary = module.check_manifest(
                    manifest, BUNDLE_ROOT, timeout=1, output_path=output
                )
            self.assertEqual(1, summary["ok"])
            self.assertIn("fallback used", summary["results"][0]["detail"])
            self.assertEqual(summary, json.loads(output.read_text(encoding="utf-8")))

    def test_manual_verification_expires_after_thirty_days(self):
        module = load_script("check_sources.py")
        recent = (date.today() - timedelta(days=30)).isoformat()
        stale = (date.today() - timedelta(days=31)).isoformat()

        def manifest(verified_on):
            return {
                "sources": [
                    {
                        "id": "manual-source",
                        "url": "https://blocked.invalid/source",
                        "manual_verified_on": verified_on,
                        "manual_verification_method": "browser review",
                    }
                ]
            }

        with mock.patch.object(module, "fetch_url", side_effect=OSError("blocked")):
            recent_summary = module.check_manifest(manifest(recent), BUNDLE_ROOT, 1)
            stale_summary = module.check_manifest(manifest(stale), BUNDLE_ROOT, 1)
        self.assertEqual("manual_ok", recent_summary["results"][0]["status"])
        self.assertEqual("review_required", stale_summary["results"][0]["status"])

    def test_fallback_must_match_inherited_version_and_strict_fails(self):
        module = load_script("check_sources.py")
        manifest = {
            "sources": [
                {
                    "id": "versioned-source",
                    "url": "https://primary.invalid/source",
                    "fallback_url": "https://fallback.example/source",
                    "version_label": "v1.1",
                }
            ]
        }

        def fake_fetch(url, timeout):
            if "primary.invalid" in url:
                raise OSError("blocked")
            return 200, b"fallback without the required marker", url

        with mock.patch.object(module, "fetch_url", side_effect=fake_fetch):
            summary = module.check_manifest(manifest, BUNDLE_ROOT, timeout=1)
        self.assertEqual("review_required", summary["results"][0]["status"])
        self.assertEqual(1, summary["review_required"])
        with (
            mock.patch.object(module, "bundle_root", return_value=BUNDLE_ROOT),
            mock.patch.object(module, "check_manifest", return_value=summary),
            mock.patch("builtins.print"),
        ):
            self.assertEqual(1, module.main(["--strict"]))


class TestSkillEntryPointTests(unittest.TestCase):
    def test_all_category_runs_without_network(self):
        module = load_script("test_skill.py")
        with mock.patch("urllib.request.urlopen") as urlopen:
            summary = module.run_tests(BUNDLE_ROOT, "all")
        urlopen.assert_not_called()
        self.assertEqual("PASS", summary["status"])
        self.assertEqual(72, summary["eval_cases"])
        self.assertEqual(41, summary["p0_cases"])


if __name__ == "__main__":
    unittest.main()
