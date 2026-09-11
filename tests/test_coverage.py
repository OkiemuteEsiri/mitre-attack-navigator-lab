import json
import tempfile
import unittest
from pathlib import Path

from src.coverage_engine import assess, metrics
from src.loader import load_coverage
from src.models import TechniqueCoverage
from src.report import render_markdown


class CoverageTests(unittest.TestCase):
    def record(self, **overrides):
        data = dict(
            technique_id="T1078", name="Valid Accounts", tactic="Initial Access",
            status="partial", severity="high", data_sources=frozenset({"Identity"}),
            detections=frozenset({"Risky sign-in"}), owner="Detection Engineering",
            validation_evidence="Synthetic validation complete", notes=""
        )
        data.update(overrides)
        return TechniqueCoverage(**data)

    def test_invalid_attack_id_rejected(self):
        with self.assertRaises(ValueError):
            self.record(technique_id="1078")

    def test_invalid_status_rejected(self):
        with self.assertRaises(ValueError):
            self.record(status="unknown")

    def test_covered_record_creates_no_finding(self):
        self.assertEqual(assess([self.record(status="covered")]), [])

    def test_gap_scores_higher_than_partial(self):
        gap = assess([self.record(status="gap")])[0]
        partial = assess([self.record(status="partial")])[0]
        self.assertGreater(gap.score, partial.score)

    def test_missing_detection_increases_score(self):
        complete = assess([self.record()])[0]
        missing = assess([self.record(detections=frozenset())])[0]
        self.assertGreater(missing.score, complete.score)

    def test_scores_are_bounded(self):
        finding = assess([self.record(status="gap", severity="critical", data_sources=frozenset(), detections=frozenset(), validation_evidence="")])[0]
        self.assertEqual(finding.score, 100)

    def test_finding_id_is_deterministic(self):
        first = assess([self.record()])[0].finding_id
        second = assess([self.record()])[0].finding_id
        self.assertEqual(first, second)

    def test_metrics_exclude_not_applicable_from_denominator(self):
        rows = [self.record(status="covered"), self.record(technique_id="T1040", status="not_applicable")]
        self.assertEqual(metrics(rows, assess(rows))["coverage_pct"], 100.0)

    def test_report_contains_finding(self):
        rows = [self.record()]
        report = render_markdown(rows, assess(rows))
        self.assertIn("T1078", report)
        self.assertIn("Remediation and Validation", report)

    def test_loader_rejects_duplicate_ids(self):
        item = {
            "technique_id":"T1078","name":"Valid Accounts","tactic":"Initial Access","status":"covered","severity":"high",
            "data_sources":["Identity"],"detections":["Rule"],"owner":"DE","validation_evidence":"evidence"
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.json"
            path.write_text(json.dumps([item, item]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_coverage(path)

    def test_loader_rejects_missing_required_field(self):
        item = {"technique_id":"T1078"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.json"
            path.write_text(json.dumps([item]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_coverage(path)

    def test_findings_sorted_highest_score_first(self):
        rows = [self.record(technique_id="T1110.003", severity="medium"), self.record(technique_id="T1190", severity="critical", status="gap")]
        findings = assess(rows)
        self.assertEqual(findings[0].technique_id, "T1190")


if __name__ == "__main__":
    unittest.main()
