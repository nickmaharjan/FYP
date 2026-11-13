import csv
import json
import tempfile
import threading
import unittest
from pathlib import Path

from mobile_df.case_library import (export_findings_csv, facets, filter_findings, filter_timeline,
                                    list_cases, load_case)
from mobile_df.core import artifact
from mobile_df.demo import create_demo
from mobile_df.pipeline import analyze


def finding(source, kind, path, detail, timestamp=None, severity="info"):
    return artifact(source, kind, path, detail, timestamp, "test" if timestamp else None, severity)


FINDINGS = [
    finding("inventory", "file", "a.db", {"size": 1}),
    finding("sqlite", "database_row", "sms.db", {"table": "sms", "values": {"body": "hello"}}, "2026-07-01T10:00:00+00:00"),
    finding("sqlite", "database_row", "sms.db", {"table": "sms", "values": {"body": "meet at 5"}}, "2026-07-15T09:00:00+00:00"),
    finding("yara", "rule_match", "payload.bin", {"rule": "Demo_Marker"}, severity="warning"),
    finding("exiftool", "metadata", "photo.png", {"values": {"=cmd": "x"}}, "2026-08-02T00:00:00+00:00"),
]


class CaseLibraryTests(unittest.TestCase):
    def test_filter_findings_by_source_severity_and_text(self):
        self.assertEqual(len(filter_findings(FINDINGS)), 4, "inventory hidden by default")
        self.assertEqual(len(filter_findings(FINDINGS, source="inventory")), 1)
        self.assertEqual([f["source"] for f in filter_findings(FINDINGS, severity="warning")], ["yara"])
        self.assertEqual(len(filter_findings(FINDINGS, query="MEET")), 1)
        self.assertEqual(filter_findings(FINDINGS)[0]["severity"], "warning", "most severe first")
        sources, severities = facets(FINDINGS)
        self.assertEqual(sources, ["exiftool", "inventory", "sqlite", "yara"])
        self.assertEqual(severities, ["warning", "info"])

    def test_filter_timeline_by_iso_prefix_range(self):
        timeline = sorted([f for f in FINDINGS if f["timestamp"]], key=lambda f: f["timestamp"])
        self.assertEqual(len(filter_timeline(timeline, start="2026-07", end="2026-07")), 2)
        self.assertEqual(len(filter_timeline(timeline, end="2026-07-01")), 1)
        self.assertEqual(len(filter_timeline(timeline, start="2026-08")), 1)
        self.assertEqual(len(filter_timeline(timeline, query="hello")), 1)

    def test_export_neutralizes_spreadsheet_formulas(self):
        with tempfile.TemporaryDirectory() as folder:
            path = export_findings_csv([finding("sqlite", "row", "=HYPERLINK(1)", {"table": "-2+3"})],
                                       Path(folder) / "out.csv")
            with path.open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.reader(stream))
            self.assertEqual(rows[1][5], "'=HYPERLINK(1)")
            self.assertEqual(rows[1][6], "table: -2+3")

    def test_list_cases_includes_incomplete_and_skips_unrelated_folders(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "not-a-case").mkdir()
            (root / "interrupted").mkdir()
            (root / "interrupted" / "status.json").write_text(json.dumps({"case_id": "CASE-X"}))
            (root / "broken").mkdir()
            (root / "broken" / "results.json").write_text("{not json")
            evidence = create_demo(root / "fixture")["evidence"]
            analyze(evidence, root / "done", "CASE-DEMO", tools=["sqlite"], config={})
            cases = list_cases(root)
            self.assertEqual({c["case_id"]: c["status"] for c in cases},
                             {"CASE-DEMO": "completed", "CASE-X": "incomplete"})
            demo = next(c for c in cases if c["case_id"] == "CASE-DEMO")
            self.assertEqual(demo["integrity"], "verified")
            self.assertTrue(demo["report"])
            self.assertEqual([c["case_id"] for c in list_cases(root, "demo")], ["CASE-DEMO"])
            self.assertEqual(load_case(root / "done")["case_id"], "CASE-DEMO")
            with self.assertRaises(ValueError):
                load_case(root / "interrupted")
            self.assertEqual(list_cases(root / "missing"), [])

    def test_cancelled_case_is_listed_as_cancelled(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = create_demo(root / "fixture")["evidence"]
            cancel = threading.Event()
            cancel.set()
            analyze(evidence, root / "cases" / "c1", "CASE-C", tools=["sqlite"], config={}, cancel=cancel)
            self.assertEqual(list_cases(root / "cases")[0]["status"], "cancelled")


if __name__ == "__main__":
    unittest.main()
