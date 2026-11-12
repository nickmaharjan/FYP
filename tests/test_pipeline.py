import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from mobile_df.pipeline import analyze


class PipelineTests(unittest.TestCase):
    def test_extraction_hashes_and_sqlite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "note.txt").write_text("test evidence", encoding="utf-8")
            with closing(sqlite3.connect(evidence / "app.db")) as db:
                db.execute("CREATE TABLE messages (id INTEGER)")
                db.execute("INSERT INTO messages VALUES (1)")
                db.commit()
            output = root / "case"
            result = analyze(evidence, output, "TEST", tools=["sqlite"])
            self.assertEqual(len(result["inventory"]), 2)
            self.assertTrue(all(len(i["sha256"]) == 64 for i in result["inventory"]))
            self.assertTrue(any(f["kind"] == "database_table" and f["detail"]["rows"] == 1
                                for f in result["findings"]))
            self.assertTrue((output / "report.html").exists())
            self.assertEqual(json.loads((output / "results.json").read_text())["case_id"], "TEST")

    def test_output_inside_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            evidence.mkdir()
            with self.assertRaises(ValueError):
                analyze(evidence, evidence / "results", "TEST")


if __name__ == "__main__":
    unittest.main()
