import io
import json
import sys
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from contextlib import closing
from pathlib import Path

from mobile_df.adapters import Context, PlasoAdapter
from mobile_df.config import doctor, load_config
from mobile_df.core import artifact, correlate, normalize_time
from mobile_df.demo import create_demo
from mobile_df.evidence import inventory, unpack
from mobile_df.pipeline import analyze
from mobile_df.runner import execute
from mobile_df.server import make_server


class EvidenceTests(unittest.TestCase):
    def test_zip_traversal_and_duplicate_paths_rejected(self):
        for entries in (("../escape.txt",), ("Foo.txt", "foo.txt")):
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                source = root / "evidence.zip"
                with zipfile.ZipFile(source, "w") as archive:
                    for name in entries:
                        archive.writestr(name, "test")
                with self.assertRaises(ValueError):
                    unpack(source, root / "extracted", 1024)
                self.assertFalse((root / "escape.txt").exists())

    def test_archive_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with zipfile.ZipFile(root / "e.zip", "w") as archive:
                archive.writestr("large.txt", "a" * 1024)
            with self.assertRaisesRegex(ValueError, "limit"):
                unpack(root / "e.zip", root / "extracted", 10)

    def test_database_without_extension_and_uncheckpointed_wal(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = root / "evidence"
            evidence.mkdir()
            with closing(sqlite3.connect(evidence / "History")) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("PRAGMA wal_autocheckpoint=0")
                db.execute("CREATE TABLE messages (body TEXT, date INTEGER)")
                db.execute("INSERT INTO messages VALUES ('Only in WAL', 1789905600000)")
                db.commit()
                before = inventory(evidence)
                result = analyze(evidence, root / "result", tools=["sqlite"], config={})
                self.assertEqual(result["integrity"]["status"], "verified")
                self.assertEqual(before, inventory(evidence))
                self.assertTrue(any(f["detail"].get("values", {}).get("body") == "Only in WAL" for f in result["findings"]))

    def test_original_modification_is_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = root / "evidence"
            evidence.mkdir()
            file = evidence / "note.txt"
            file.write_text("original")
            def change_source(message):
                if message == "Verifying original evidence after analysis":
                    file.write_text("changed externally")
            result = analyze(evidence, root / "result", tools=[], config={}, progress=change_source)
            self.assertEqual(result["integrity"]["status"], "changed")
            self.assertEqual(result["status"], "completed_with_warnings")

    def test_archive_pipeline_and_existing_case_protection(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture = create_demo(root / "fixture")
            with zipfile.ZipFile(root / "e.zip", "w") as archive:
                for path in fixture["evidence"].rglob("*"):
                    if path.is_file():
                        archive.write(path, path.relative_to(fixture["evidence"]))
            result = analyze(root / "e.zip", root / "result", tools=["sqlite"], config={})
            self.assertEqual(result["status"], "completed")
            self.assertTrue(result["timeline"])
            with self.assertRaisesRegex(ValueError, "already exists"):
                analyze(root / "e.zip", root / "result", tools=["sqlite"])


class OrchestrationTests(unittest.TestCase):
    def test_failed_tool_does_not_stop_other_analysis(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture = create_demo(root / "fixture")
            result = analyze(fixture["evidence"], root / "result", tools=["sqlite", "aleapp"],
                             config={"commands": {"aleapp": [sys.executable, "-c", "import sys;sys.exit(7)"]}})
            runs = {r["tool"]: r for r in result["tool_runs"]}
            self.assertEqual(runs["sqlite"]["status"], "success")
            self.assertEqual(runs["aleapp"]["status"], "failed")
            self.assertEqual(runs["aleapp"]["steps"][0]["exit_code"], 7)
            self.assertEqual(result["integrity"]["status"], "verified")

    def test_timeout_and_cancel_are_recorded(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            command = [sys.executable, "-c", "import time;time.sleep(20)"]
            result = execute("timeout", command, root, 0.2)
            self.assertEqual(result["status"], "timeout")
            event = threading.Event()
            event.set()
            result = execute("cancel", command, root, 10, event)
            self.assertEqual(result["status"], "cancelled")

    def test_plaso_contract_and_provenance(self):
        # Contract fixture only: this does NOT claim a real Plaso runtime was exercised.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = root / "evidence"
            evidence.mkdir()
            extraction = root / "extract.py"
            extraction.write_text("import sys,pathlib\npathlib.Path(sys.argv[sys.argv.index('--storage-file')+1]).write_bytes(b'fixture')\n")
            export = root / "export.py"
            export.write_text("import sys,pathlib,json\npathlib.Path(sys.argv[sys.argv.index('-w')+1]).write_text(json.dumps({'timestamp':1789905600000000,'filename':'sms.db','message':'fixture event'})+'\\n')\n")
            ctx = Context(evidence, root, "directory", {"commands": {
                "plaso": [sys.executable, str(extraction)], "psort": [sys.executable, str(export)]}})
            findings = PlasoAdapter().run(ctx)
            self.assertEqual(len(ctx.steps), 2)
            self.assertEqual(findings[0]["timestamp"], "2026-09-20T12:00:00+00:00")
            self.assertEqual(findings[0]["provenance"]["line"], 1)

    def test_row_limit_is_explicit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = root / "evidence"
            evidence.mkdir()
            with closing(sqlite3.connect(evidence / "app.db")) as db:
                db.execute("CREATE TABLE sample (id INTEGER)")
                db.executemany("INSERT INTO sample VALUES (?)", [(i,) for i in range(5)])
                db.commit()
            result = analyze(evidence, root / "case", tools=["sqlite"], max_rows=2, config={})
            run = next(r for r in result["tool_runs"] if r["tool"] == "sqlite")
            self.assertEqual(run["status"], "partial")
            self.assertEqual(len([f for f in result["findings"] if f["kind"] == "database_row"]), 2)

    def test_correlations_and_timezones(self):
        one = artifact("sqlite", "row", "a.db", {"url": "https://test.example/path"})
        two = artifact("mvt", "row", "b.json", {"url": "https://test.example/path"})
        links = correlate([one, two])
        self.assertTrue(any(c["type"] == "url" and len(c["sources"]) == 2 for c in links))
        self.assertIsNone(normalize_time("2026-09-20 12:00:00"))
        self.assertEqual(normalize_time("2026-09-20T17:45:00+05:45"), "2026-09-20T12:00:00+00:00")

    def test_report_does_not_execute_evidence_html(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture = create_demo(root / "fixture")
            marker = '</script><img src=x onerror="alert(1)">'
            result = analyze(fixture["evidence"], root / "result", marker, tools=["sqlite"], config={})
            text = (root / "result/report.html").read_text(encoding="utf-8")
            self.assertNotIn(marker, text)
            self.assertIn("\\u003c/script", text)


class DashboardTests(unittest.TestCase):
    def test_local_api_requires_token_and_rejects_other_origins(self):
        with tempfile.TemporaryDirectory() as folder:
            server = make_server(folder, {}, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(base + "/api/cases")
                self.assertEqual(error.exception.code, 401)
                request = urllib.request.Request(base + "/api/tools", headers={"Authorization": "Bearer " + server.token})
                with urllib.request.urlopen(request) as response:
                    self.assertTrue(json.load(response)["sqlite"]["available"])
                request.add_header("Origin", "https://unrelated.example")
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(request)
                self.assertEqual(error.exception.code, 403)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


class InstalledToolsTests(unittest.TestCase):
    def test_real_five_tool_extraction_and_sleuthkit_image(self):
        config = load_config()
        ready = doctor(config)
        required = ["sqlite", "yara", "exiftool", "aleapp", "mvt", "sleuthkit"]
        if not all(ready[name]["available"] for name in required):
            self.skipTest("Run scripts/setup.ps1 to enable installed-tool integration tests")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture = create_demo(root / "fixture")
            result = analyze(**fixture, output=root / "case", tools=required, config=config)
            runs = {r["tool"]: r for r in result["tool_runs"]}
            for name in required[:-1]:
                self.assertEqual(runs[name]["status"], "success", (name, runs[name]))
                self.assertGreater(runs[name]["findings_count"], 0)
            self.assertTrue(any(f["source"] == "mvt" and f["kind"] == "indicator" for f in result["findings"]))
            self.assertEqual(result["integrity"]["status"], "verified")
            image = analyze(root / "fixture/training-fat12.img", root / "image-case", tools=["sleuthkit", "yara"], yara_rules=fixture["yara_rules"], config=config)
            self.assertEqual(image["status"], "completed")
            self.assertTrue(any(f["source"] == "yara" and f["path"].lower() == "note.txt" for f in image["findings"]))


if __name__ == "__main__":
    unittest.main()
