"""SQLite on real app databases: binary data in TEXT columns, and unreadable databases reported as partial."""
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from mobile_df.pipeline import analyze


def chrome_like(path):
    """A History-style database whose TEXT column holds protobuf bytes, as Chrome's does."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE meta (key TEXT, value TEXT)")
        db.execute("INSERT INTO meta VALUES ('version', '42')")
        db.execute("INSERT INTO meta VALUES ('blob_as_text', CAST(x'0a8d0108ffee0212' AS TEXT))")
        db.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)")
        db.execute("INSERT INTO urls VALUES (1, 'https://example.org/visited')")
        db.commit()


class SQLiteRobustnessTests(unittest.TestCase):
    def test_binary_text_keeps_the_database(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            chrome_like(root / "evidence/data/data/com.android.chrome/app_chrome/Default/History")
            result = analyze(root / "evidence", root / "case", tools=["sqlite"], config={})
            run = next(r for r in result["tool_runs"] if r["tool"] == "sqlite")
            self.assertEqual(run["status"], "success", run)
            rows = {(f["detail"]["table"], f["detail"]["values"].get("key") or f["detail"]["values"].get("url")): f
                    for f in result["findings"] if f["kind"] == "database_row"}
            self.assertIn(("urls", "https://example.org/visited"), rows, "tables after the binary value are still read")
            binary = rows[("meta", "blob_as_text")]["detail"]["values"]["value"]
            self.assertEqual(binary["type"], "blob")
            self.assertEqual(binary["bytes"], 8)
            self.assertEqual(rows[("meta", "version")]["detail"]["values"]["value"], "42")
            self.assertFalse([f for f in result["findings"] if f["kind"] == "analysis_error"])

    def test_unreadable_database_is_partial_not_failed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            chrome_like(root / "evidence/good/History")
            broken = root / "evidence/broken/cache.db"
            broken.parent.mkdir(parents=True)
            broken.write_bytes(b"SQLite format 3\x00" + b"\xff" * 4096)
            result = analyze(root / "evidence", root / "case", tools=["sqlite"], config={})
            run = next(r for r in result["tool_runs"] if r["tool"] == "sqlite")
            self.assertEqual(run["status"], "partial", run)
            self.assertIn("1 of 2 databases", run["reason"])
            self.assertIn("broken/cache.db", run["reason"])
            self.assertTrue(any(f["kind"] == "database_row" and f["path"] == "good/History" for f in result["findings"]))
            self.assertTrue(any(f["kind"] == "analysis_error" and f["path"] == "broken/cache.db" for f in result["findings"]))
            self.assertEqual(result["status"], "completed_with_warnings")

    def test_every_database_unreadable_is_still_failed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "evidence").mkdir()
            (root / "evidence/only.db").write_bytes(b"SQLite format 3\x00" + b"\xff" * 4096)
            result = analyze(root / "evidence", root / "case", tools=["sqlite"], config={})
            run = next(r for r in result["tool_runs"] if r["tool"] == "sqlite")
            self.assertEqual(run["status"], "failed", "nothing was read, so this is not a partial result")


if __name__ == "__main__":
    unittest.main()
