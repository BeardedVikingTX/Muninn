import json
import tempfile
import unittest
from pathlib import Path

from core.confidence import assess_finding, ScopeStatus, Evidence, EvidenceKind, EvidenceQuality
from core.reporting import (Eligibility, ReportFinding, ReportingError, RewardRange,
                            ScanReport, Severity, render_html, render_json,
                            render_markdown, write_report)


def finding(fid="M-1", title="Example finding"):
    assessment = assess_finding(finding_id=fid, scope=ScopeStatus.UNKNOWN, evidence=[])
    return ReportFinding(fid, title, "access_control", Severity.MEDIUM,
                         assessment, "Requires manual verification")


class ReportingTests(unittest.TestCase):
    def test_empty(self):
        r = ScanReport("scan-1", "program-1", ())
        self.assertEqual(json.loads(render_json(r))["finding_count"], 0)
        self.assertIn("does not establish", render_markdown(r))

    def test_structured(self):
        r = ScanReport("scan-1", "program-1", (finding(),))
        d = json.loads(render_json(r))
        self.assertEqual(d["findings"][0]["status"], "inconclusive")
        self.assertEqual(d["status_counts"]["inconclusive"], 1)

    def test_duplicate_finding(self):
        with self.assertRaises(ReportingError):
            ScanReport("scan-1", "program-1", (finding(), finding()))

    def test_assessment_mismatch(self):
        a = assess_finding(finding_id="other", scope=ScopeStatus.UNKNOWN, evidence=[])
        with self.assertRaises(ReportingError):
            ReportFinding("M-1", "title", "access_control", Severity.LOW, a, "summary")

    def test_html_escaped(self):
        r = ScanReport("scan-1", "program-1", (finding(title='<script>alert(1)</script>'),))
        html = render_html(r)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)

    def test_redact_bearer(self):
        f = ReportFinding("M-1", "title", "access_control", Severity.LOW,
                          assess_finding(finding_id="M-1", scope=ScopeStatus.UNKNOWN, evidence=[]),
                          "Authorization: Bearer abcdef123456")
        self.assertNotIn("abcdef123456", json.dumps(f.as_dict()))

    def test_reward_not_guaranteed(self):
        r = ScanReport("scan-1", "program-1", (ReportFinding(
            "M-1", "title", "access_control", Severity.MEDIUM,
            assess_finding(finding_id="M-1", scope=ScopeStatus.UNKNOWN, evidence=[]),
            "summary", reward_range=RewardRange("USD", 1000, 2000),
            eligibility=Eligibility.POTENTIALLY_ELIGIBLE),))
        self.assertIn("not a payout prediction", render_markdown(r))

    def test_reward_validation(self):
        with self.assertRaises(ReportingError):
            RewardRange("USD", 2000, 1000)

    def test_private_write(self):
        with tempfile.TemporaryDirectory() as d:
            paths = write_report(ScanReport("scan-1", "program-1", (finding(),)), Path(d) / "reports")
            self.assertEqual(set(paths), {"json", "md", "html"})
            self.assertEqual(json.loads(paths["json"].read_text())["finding_count"], 1)
            for path in paths.values():
                self.assertTrue(path.is_file())

    def test_symlink_directory_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "real").mkdir()
            (root / "link").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaises(ReportingError):
                write_report(ScanReport("scan-1", "program-1", ()), root / "link")

    def test_symlink_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "target").write_text("original")
            (root / "report.json").symlink_to(root / "target")
            with self.assertRaises(ReportingError):
                write_report(ScanReport("scan-1", "program-1", ()), root)
            self.assertEqual((root / "target").read_text(), "original")

    def test_invalid_timestamp(self):
        with self.assertRaises(ReportingError):
            ScanReport("scan-1", "program-1", (), created_at="2026-11-21T19:00:00")


if __name__ == "__main__":
    unittest.main()

