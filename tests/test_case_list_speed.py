"""The case list reads only the header and footer of results.json, falls back safely, and caches rows."""
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from mobile_df import case_library
from mobile_df.case_library import list_cases
from mobile_df.core import write_json


def big_result(case_id):
    finding = {"source": "sqlite", "kind": "database_row", "path": "data/x.db",
               "detail": {"values": {"body": "a" * 200, "status": "not-a-top-level-key"}}}
    return {"schema_version": 2, "case_id": case_id, "status": "completed_with_warnings",
            "evidence": "C:\\evidence\\phone", "evidence_kind": "directory",
            "started_utc": "2026-11-26T10:00:00+00:00", "completed_utc": "2026-11-26T11:00:00+00:00",
            "inventory": [{"path": f"f{i}", "size": i} for i in range(20000)],
            "findings": [finding] * 20000, "correlations": [], "timeline": [],
            "integrity": {"status": "verified"}, "warnings": [], "parameters": {}, "limitations": [],
            "duration_seconds": 3600.0,
            "metrics": {"files": 20000, "findings": 20000, "timeline_events": 7, "correlations": 3}}


class CaseListSpeedTests(unittest.TestCase):
    def setUp(self):
        case_library._SUMMARY_CACHE.clear()

    def test_large_case_listed_without_a_full_load(self):
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder) / "case1"
            case.mkdir()
            write_json(case / "results.json", big_result("CASE-BIG"))
            with mock.patch.object(case_library, "_load", side_effect=AssertionError("full load")):
                [row] = list_cases(folder)
            self.assertEqual((row["case_id"], row["status"], row["integrity"]), ("CASE-BIG", "completed_with_warnings", "verified"))
            self.assertEqual((row["findings"], row["timeline_events"], row["correlations"]), (20000, 7, 3))
            self.assertEqual((row["evidence"], row["started_utc"]), ("C:\\evidence\\phone", "2026-11-26T10:00:00+00:00"))

    def test_other_layouts_fall_back_to_a_full_load(self):
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder) / "case1"
            case.mkdir()
            compact = big_result("CASE-COMPACT")
            compact["findings"] = compact["findings"][:3]
            (case / "results.json").write_text(json.dumps(compact), encoding="utf-8")   # no indentation
            [row] = list_cases(folder)
            self.assertEqual((row["case_id"], row["integrity"], row["findings"]), ("CASE-COMPACT", "verified", 20000))

    def test_rows_are_cached_until_results_change(self):
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder) / "case1"
            case.mkdir()
            write_json(case / "results.json", big_result("CASE-ONE"))
            list_cases(folder)
            with mock.patch.object(case_library, "_summary_fields", side_effect=AssertionError("re-read")):
                self.assertEqual(list_cases(folder)[0]["case_id"], "CASE-ONE")
                self.assertIsNone(list_cases(folder)[0]["report"])
                (case / "report.html").write_text("<html></html>")
                self.assertIsNotNone(list_cases(folder)[0]["report"], "report presence is checked every time")
            time.sleep(0.01)
            write_json(case / "results.json", big_result("CASE-RENAMED"))
            self.assertEqual(list_cases(folder)[0]["case_id"], "CASE-RENAMED")


if __name__ == "__main__":
    unittest.main()
