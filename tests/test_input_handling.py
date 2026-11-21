"""Unsupported, damaged and encrypted inputs must give a visible outcome, never a silent empty case.

Test plan section 5 ("Encrypted / unsupported input"). All fixtures are synthetic.
"""
import sqlite3
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path

from mobile_df.evidence import detect_kind
from mobile_df.pipeline import analyze


def encrypted_zip(path):
    """A ZIP whose entry is flagged as encrypted (the flag is what extraction checks)."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("secret.db", b"SQLite format 3\x00" + b"x" * 100)
    data = bytearray(path.read_bytes())
    data[6] |= 1                                   # local file header: general purpose flag bit 0
    data[data.find(b"PK\x01\x02") + 8] |= 1        # central directory header: same flag
    path.write_bytes(bytes(data))


class InputHandlingTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)

    def tearDown(self):
        self.folder.cleanup()

    def test_encrypted_zip_fails_with_reason(self):
        evidence = self.root / "locked.zip"
        encrypted_zip(evidence)
        result = analyze(evidence, self.root / "case", tools=["sqlite"], config={})
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("encrypted" in warning for warning in result["warnings"]), result["warnings"])
        self.assertTrue((self.root / "case/report.html").exists(), "a failed case still gets a report")

    def test_damaged_archive_is_not_treated_as_disk_image(self):
        valid = self.root / "valid.zip"
        with zipfile.ZipFile(valid, "w") as archive:
            archive.writestr("note.txt", "synthetic")
        for name in ("partial.zip", "partial.tar.gz", "PARTIAL.TGZ"):
            with self.subTest(name=name):
                damaged = self.root / name
                damaged.write_bytes(valid.read_bytes()[:30])
                with self.assertRaisesRegex(ValueError, "not a readable ZIP or TAR"):
                    detect_kind(damaged)
                with self.assertRaisesRegex(ValueError, "--kind image"):
                    analyze(damaged, self.root / ("case-" + name), tools=["sqlite"], config={})
                self.assertFalse((self.root / ("case-" + name)).exists(), "refused before a case folder is made")
        # A real .tar.gz cut off early (like a stopped download) made tarfile.is_tarfile raise
        # EOFError before the check above could run; it must give the same visible refusal.
        source = self.root / "n.txt"
        source.write_text("synthetic " * 50)
        with tarfile.open(self.root / "full.tar.gz", "w:gz") as archive:
            archive.add(source, "n.txt")
        for size in (5, 20, 60):
            with self.subTest(truncated_bytes=size):
                cut = self.root / f"cut{size}.tar.gz"
                cut.write_bytes((self.root / "full.tar.gz").read_bytes()[:size])
                with self.assertRaisesRegex(ValueError, "not a readable ZIP or TAR"):
                    detect_kind(cut)
        # The investigator can still override the guess explicitly.
        self.assertEqual(detect_kind(self.root / "partial.zip", "image"), "image")
        unnamed = self.root / "disk.img"
        unnamed.write_bytes(b"\xeb\x3c\x90" + b"\x01" * 1021)   # starts like a boot sector
        self.assertEqual(detect_kind(unnamed), "image")

    def test_corrupt_database_is_a_partial_tool_not_an_empty_success(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "broken.db").write_bytes(b"SQLite format 3\x00" + b"\xff" * 2000)
        with closing(sqlite3.connect(evidence / "good.db")) as db:
            db.execute("CREATE TABLE t (v TEXT)")
            db.execute("INSERT INTO t VALUES ('kept')")
            db.commit()
        result = analyze(evidence, self.root / "case", tools=["sqlite"], config={})
        run = next(r for r in result["tool_runs"] if r["tool"] == "sqlite")
        # One of two databases was read, so the run is partial (not success, not failed) and says which one failed.
        self.assertEqual(run["status"], "partial")
        self.assertIn("broken.db", run["reason"])
        self.assertEqual(result["status"], "completed_with_warnings")
        errors = [f for f in result["findings"] if f["kind"] == "analysis_error"]
        self.assertEqual([f["path"] for f in errors], ["broken.db"])
        self.assertTrue(any(f["detail"].get("values", {}).get("v") == "kept" for f in result["findings"]),
                        "one bad database must not hide the others")
        self.assertEqual(result["integrity"]["status"], "verified")

    def test_no_selected_tool_applies_is_a_warning(self):
        evidence = self.root / "backup.ab"
        evidence.write_bytes(b"ANDROID BACKUP\n5\n1\nAES-256\n")   # header of an encrypted backup
        result = analyze(evidence, self.root / "case", tools=["sqlite"], config={})
        self.assertEqual(result["status"], "completed_with_warnings")
        self.assertTrue(any("None of the selected tools" in w and "sqlite not_applicable" in w
                            for w in result["warnings"]), result["warnings"])

    def test_empty_evidence_folder_is_a_warning(self):
        evidence = self.root / "empty"
        evidence.mkdir()
        result = analyze(evidence, self.root / "case", tools=["sqlite"], config={})
        self.assertEqual(result["status"], "completed_with_warnings")
        self.assertIn("Evidence contains no files; nothing was analysed", result["warnings"])

    def test_no_tools_selected_does_not_add_the_warning(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "note.txt").write_text("synthetic")
        result = analyze(evidence, self.root / "case", tools=[], config={})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["warnings"], [])


if __name__ == "__main__":
    unittest.main()
