import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

from mobile_df.demo import create_demo
from mobile_df.handoff import MANIFEST_NAME, default_filename, export_case, main, verify_handoff
from mobile_df.pipeline import analyze


class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        root = Path(cls.folder.name)
        fixture = create_demo(root / "fixture")
        cls.case = root / "case"
        cls.result = analyze(fixture["evidence"], cls.case, "CASE/HANDOFF 1", tools=["sqlite", "yara"],
                             yara_rules=fixture["yara_rules"], config={})
        # Simulate native tool output, which is optional in a handoff.
        (cls.case / "tools").mkdir(exist_ok=True)
        (cls.case / "tools" / "native.txt").write_text("raw tool output")

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def out(self, name):
        path = Path(self.folder.name) / "out" / name
        path.parent.mkdir(exist_ok=True)
        return path

    def test_export_contents_hashes_and_exclusions(self):
        summary = export_case(self.case, self.out("a.zip"))
        zip_path = Path(summary["zip"])
        self.assertEqual(hashlib.sha256(zip_path.read_bytes()).hexdigest(), summary["sha256"])
        self.assertEqual(Path(summary["sha256_file"]).read_text().split(), [summary["sha256"], "a.zip"])
        with zipfile.ZipFile(zip_path) as archive:
            names = archive.namelist()
            root = "CASE_HANDOFF_1/"
            self.assertTrue(all(name.startswith(root) for name in names), names)
            for required in ("report.html", "results.json", "timeline.csv", "manifest.json", "audit.jsonl",
                             MANIFEST_NAME, "HANDOFF-README.txt"):
                self.assertIn(root + required, names)
            self.assertTrue(any(name.startswith(root + "logs/") for name in names))
            self.assertTrue(any(name.startswith(root + "inputs/") for name in names), "YARA rules used are kept")
            self.assertFalse(any("/working/" in name for name in names), "evidence copies never packaged")
            self.assertFalse(any("/tools/" in name for name in names), "tool output is opt-in")
            manifest = json.loads(archive.read(root + MANIFEST_NAME))
            self.assertEqual((manifest["case_id"], manifest["evidence_integrity"]), ("CASE/HANDOFF 1", "verified"))
            for entry in manifest["files"]:
                self.assertEqual(hashlib.sha256(archive.read(root + entry["path"])).hexdigest(), entry["sha256"])
        report = verify_handoff(zip_path)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["zip_hash"], "match")

    def test_tool_output_only_when_requested(self):
        summary = export_case(self.case, self.out("b.zip"), include_tool_output=True)
        with zipfile.ZipFile(summary["zip"]) as archive:
            self.assertIn("CASE_HANDOFF_1/tools/native.txt", archive.namelist())
            self.assertFalse(any("/working/" in name for name in archive.namelist()))

    def test_verify_detects_tampering(self):
        summary = export_case(self.case, self.out("c.zip"))
        tampered = self.out("tampered.zip")
        with zipfile.ZipFile(summary["zip"]) as source, zipfile.ZipFile(tampered, "w") as target:
            for item in source.infolist():
                data = source.read(item)
                if item.filename.endswith("/report.html"):
                    data = data.replace(b"</body>", b"<p>edited</p></body>")
                if not item.filename.endswith("/timeline.csv"):
                    target.writestr(item, data)
            target.writestr("CASE_HANDOFF_1/extra.txt", "added later")
        report = verify_handoff(tampered)
        self.assertFalse(report["ok"])
        self.assertIn("changed: report.html", report["problems"])
        self.assertIn("missing: timeline.csv", report["problems"])
        self.assertIn("unexpected file: extra.txt", report["problems"])
        Path(summary["sha256_file"]).write_text("0" * 64 + "  c.zip\n")
        self.assertIn("ZIP hash does not match its .sha256 file", verify_handoff(summary["zip"])["problems"])

    def test_refusals(self):
        with self.assertRaisesRegex(ValueError, "outside the case folder"):
            export_case(self.case, self.case / "inside.zip")
        with self.assertRaisesRegex(ValueError, ".zip"):
            export_case(self.case, self.out("report.tar"))
        existing = self.out("exists.zip")
        existing.write_text("keep me")
        with self.assertRaisesRegex(ValueError, "already exists"):
            export_case(self.case, existing)
        self.assertEqual(existing.read_text(), "keep me")
        unfinished = Path(self.folder.name) / "unfinished"
        unfinished.mkdir()
        (unfinished / "status.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "finished cases"):
            export_case(unfinished, self.out("u.zip"))
        self.assertFalse(self.out("u.zip").exists())
        self.assertTrue(default_filename(self.result).startswith("CASE_HANDOFF_1-handoff-"))

    def test_command_line(self):
        target = self.out("cli.zip")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["export", str(self.case), str(target)]), 0)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(main(["verify", str(target)]), 0)
        self.assertTrue(json.loads(buffer.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()
