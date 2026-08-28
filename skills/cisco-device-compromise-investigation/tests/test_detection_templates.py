import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "detections" / "templates"


class SuppressionTemplateContractTests(unittest.TestCase):
    def test_sentinel_generates_expected_rows_and_zero_fills_current_counts(self):
        text = (TEMPLATES / "sentinel-kql.yaml").read_text(encoding="utf-8")
        self.assertIn("ExpectedRows", text)
        self.assertIn("range(", text)
        self.assertIn("join kind=leftouter", text)
        self.assertRegex(text, r"coalesce\([^,\r\n]*TargetCount[^,\r\n]*,\s*0\)")
        self.assertNotIn("TotalCount", text)

    def test_sentinel_health_is_separate_from_target_count(self):
        text = (TEMPLATES / "sentinel-kql.yaml").read_text(encoding="utf-8")
        self.assertIn("DeviceCollectorHealth", text)
        self.assertIn("DeviceEventCount", text)
        self.assertIn("CollectorHealthy", text)
        self.assertNotRegex(text, r"TargetCount\s*>\s*0")

    def test_splunk_generates_expected_rows_and_zero_fills_current_counts(self):
        text = (TEMPLATES / "splunk-spl.yaml").read_text(encoding="utf-8")
        self.assertIn("<BASELINE_LOOKUP>", text)
        self.assertIn("mvrange(", text)
        self.assertIn("join type=left", text)
        self.assertIn("fillnull value=0 target_count", text)
        self.assertNotIn("total_count", text)

    def test_splunk_health_is_separate_from_target_count(self):
        text = (TEMPLATES / "splunk-spl.yaml").read_text(encoding="utf-8")
        self.assertIn("device_event_count", text)
        self.assertIn("collector_healthy", text)
        self.assertNotRegex(text, r"target_count\s*>\s*0")


if __name__ == "__main__":
    unittest.main()
