"""Larger SQLite fixture (test plan section 5): row counts, truncation, WAL, Unicode, odd names."""
import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from mobile_df.evaluation import evaluate, evaluate_case
from mobile_df.pipeline import analyze
from mobile_df.sqlite_fixture import UNICODE_NAME, create_sqlite_fixture, main


def checks(evaluation):
    return {c["id"]: c for c in evaluation["checks"]}


class SQLiteFixtureTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)

    def tearDown(self):
        self.folder.cleanup()

    def run_case(self, max_rows=100, analysed_with=None):
        fixture = create_sqlite_fixture(self.root / "fixture", max_rows)
        options = dict(fixture["options"], max_rows=analysed_with or max_rows)
        result = analyze(fixture["evidence"], self.root / "case", "SQLITE-FIXTURE", config={}, **options)
        return fixture, result, evaluate_case(self.root / "case", fixture["expected"])

    def test_every_expectation_passes_at_the_intended_row_limit(self):
        for max_rows in (100, 50):
            with self.subTest(max_rows=max_rows):
                if self.root.exists():
                    self.folder.cleanup()
                    self.folder = tempfile.TemporaryDirectory()
                    self.root = Path(self.folder.name)
                _, result, evaluation = self.run_case(max_rows)
                self.assertEqual(evaluation["verdict"], "pass", checks(evaluation))
                self.assertEqual(evaluation["summary"], {"pass": 7, "fail": 0, "skipped": 0, "unsupported": 0})
                self.assertEqual(result["status"], "completed_with_warnings")   # partial is a visible warning
                self.assertEqual(result["integrity"]["status"], "verified")

    def test_wal_rows_exist_only_in_the_wal_file(self):
        fixture = create_sqlite_fixture(self.root / "fixture")
        files = fixture["evidence"] / "data/data/org.telegram.messenger/files"
        self.assertTrue((files / "cache4.db-wal").stat().st_size > 0)
        alone = self.root / "alone.db"
        alone.write_bytes((files / "cache4.db").read_bytes())
        with closing(sqlite3.connect(alone)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM messages_v2").fetchone()[0], 0,
                             "the fixture must not pass by accident if WAL handling breaks")

    def test_non_databases_are_ignored_and_values_survive(self):
        _, result, _ = self.run_case()
        paths = {f["path"] for f in result["findings"] if f["source"] == "sqlite"}
        self.assertFalse(any(p.endswith(("notes.db", "empty.db", "-wal")) for p in paths), paths)
        self.assertFalse([f for f in result["findings"] if f["kind"] == "analysis_error"])
        names = [f["detail"]["values"].get("name") for f in result["findings"]
                 if f["kind"] == "database_row" and f["detail"].get("table") == "calls"]
        self.assertIn(UNICODE_NAME, names)

    def test_wrong_row_limit_is_reported_not_hidden(self):
        _, _, evaluation = self.run_case(max_rows=100, analysed_with=500)
        found = checks(evaluation)
        self.assertEqual(evaluation["verdict"], "fail")
        self.assertEqual(found["parameters"]["observed"], {"max_rows": 500})
        self.assertEqual(found["sqlite_truncated_tables"]["observed"], [])
        self.assertEqual(found["tool_status"]["observed"], {"sqlite": "success"})

    def test_missing_rows_and_tables_fail_with_details(self):
        fixture, result, _ = self.run_case()
        expected = json.loads(fixture["expected"].read_text(encoding="utf-8"))
        wal_table = "data/data/org.telegram.messenger/files/cache4.db::messages_v2"
        result["findings"] = [f for f in result["findings"]
                              if not (f["path"].endswith("cache4.db") and f["source"] == "sqlite")]
        found = checks(evaluate(result, expected))
        self.assertEqual(found["sqlite_table_rows"]["status"], "fail")
        self.assertEqual(found["sqlite_table_rows"]["observed"][wal_table], "missing")
        self.assertEqual(found["sqlite_row_values"]["status"], "fail")
        self.assertEqual([m["table"] for m in found["sqlite_row_values"]["observed"]["missing"]], [wal_table])
        self.assertEqual(found["sqlite_database_files"]["observed"], 5)

    def test_command_line_and_refusals(self):
        out = self.root / "run"
        with contextlib.redirect_stdout(io.StringIO()) as printed, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(out), "--max-rows", "60"]), 0)
        self.assertEqual(json.loads(printed.getvalue())["verdict"], "pass")
        self.assertEqual(json.loads((out / "case/evaluation.json").read_text(encoding="utf-8"))["verdict"], "pass")
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            main([str(out)])                                  # existing output is never overwritten
        with self.assertRaisesRegex(ValueError, "at least 50"):
            create_sqlite_fixture(self.root / "small", max_rows=49)


if __name__ == "__main__":
    unittest.main()
