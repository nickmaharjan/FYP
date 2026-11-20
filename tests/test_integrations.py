"""Milestone checks: image timelines, clear partial states, tool registry, log review and benchmark."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from mobile_df.adapters import parse_bodyfile, timestamp_anomaly
from mobile_df.benchmark import markdown, run_benchmark
from mobile_df.case_library import step_logs
from mobile_df.core import artifact
from mobile_df.evaluation import evaluate
from mobile_df.pipeline import analyze
from mobile_df.registry import TOOLS, detect_version, load_packs, notices, verify_packs
from mobile_df.core import TOOL_NAMES

BODY = [
    "0|/$MFT ($FILE_NAME)|0-48-3|r/rr-xr-xr-x|0|0|74|1230763442|1230763442|1230763442|1230763442\n",
    "0|/$MFT|0-128-1|r/rr-xr-xr-x|0|0|49152|1230763442|1230763442|1230763442|1230763442\n",
    "0|/RAW/report.pdf ($FILE_NAME)|40-48-2|r/rrwxrwxrwx|0|0|102|1230765380|1230765380|1230765380|1230765380\n",
    "0|/RAW/report.pdf|40-128-1|r/rrwxrwxrwx|0|0|1001647|1230765380|1230765330|1230765336|1230700000\n",
    "0|/old|notes.txt (deleted)|52-128-1|r/rrw-rw-rw-|0|0|12|0|1230765000|0|0\n",
    "garbage line without enough columns\n",
]


class BodyFileTests(unittest.TestCase):
    def test_parses_times_file_name_attribute_deleted_and_pipes(self):
        entries = {entry["path"]: entry for entry in parse_bodyfile(BODY)}
        self.assertEqual(sorted(entries), ["$MFT", "RAW/report.pdf", "old|notes.txt"])
        report = entries["RAW/report.pdf"]
        self.assertEqual(report["size"], 1001647)
        self.assertEqual(report["times"]["modified"], "2008-12-31T23:15:30+00:00")
        self.assertEqual(report["file_name_times"]["created"], "2008-12-31T23:16:20+00:00")
        deleted = entries["old|notes.txt"]
        self.assertTrue(deleted["deleted"])
        self.assertIsNone(deleted["times"]["accessed"], "zero epoch means no time, not 1970")
        # $STANDARD_INFORMATION created long before $FILE_NAME created: possible time manipulation.
        self.assertIsNotNone(timestamp_anomaly(report))
        self.assertIsNone(timestamp_anomaly(entries["$MFT"]))


class ExifToolPartialTests(unittest.TestCase):
    def test_per_file_errors_are_partial_with_reason(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "ok.jpg").write_bytes(b"jpeg")
            (evidence / "locked.jpg").write_bytes(b"encrypted")
            fake = root / "fake_exiftool.py"
            fake.write_text(
                "import json, sys\n"
                "target = sys.argv[-1]\n"
                "print(json.dumps([{'SourceFile': target + '/ok.jpg', 'File:FileType': 'JPEG'},\n"
                "                  {'SourceFile': target + '/locked.jpg', 'ExifTool:Error': 'File format error'}]))\n"
                "sys.exit(1)\n")
            config = {"commands": {"exiftool": [sys.executable, str(fake)]}}
            result = analyze(evidence, root / "case", tools=["exiftool"], config=config)
            run = next(r for r in result["tool_runs"] if r["tool"] == "exiftool")
            self.assertEqual(run["status"], "partial")
            self.assertIn("could not read 1 of 2 files", run["reason"])
            self.assertIn("locked.jpg", run["reason"])
            self.assertEqual(run["findings_count"], 2)
            severities = {f["path"]: f["severity"] for f in result["findings"] if f["source"] == "exiftool"}
            self.assertEqual(severities, {"ok.jpg": "info", "locked.jpg": "warning"})
            self.assertEqual(result["status"], "completed_with_warnings")


class RegistryTests(unittest.TestCase):
    def test_every_tool_is_described_and_packs_are_valid(self):
        self.assertEqual(set(TOOLS), set(TOOL_NAMES))
        for name in TOOL_NAMES:
            self.assertTrue(TOOLS[name]["license"] and TOOLS[name]["homepage"], name)
            self.assertIn(TOOLS[name]["title"], notices())
        packs = load_packs()
        self.assertEqual(set(packs), {"aleapp", "sleuthkit", "exiftool"})
        self.assertEqual(detect_version("sqlite", None)[1], "Python sqlite3 library")
        self.assertEqual(detect_version("exiftool", None), (None, "not installed"))

    def test_verify_packs_reports_match_mismatch_and_missing(self):
        with tempfile.TemporaryDirectory() as folder:
            tools = Path(folder)
            good, bad = b"good pack", b"tampered pack"
            packs = {"good": {"version": "1", "sha256": hashlib.sha256(good).hexdigest().upper(), "binary": "good/x.exe"},
                     "bad": {"version": "1", "sha256": hashlib.sha256(good).hexdigest(), "binary": "bad/x.exe"},
                     "gone": {"version": "1", "sha256": "0" * 64, "binary": "gone/x.exe"}}
            (tools / "good.zip").write_bytes(good)
            (tools / "bad.zip").write_bytes(bad)
            report = verify_packs(packs, tools)
            self.assertEqual({k: v["status"] for k, v in report.items()},
                             {"good": "verified", "bad": "MISMATCH", "gone": "missing"})

    def test_bad_pack_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "packs.json"
            path.write_text(json.dumps({"packs": [{"name": "x", "version": "1", "sha256": "abc"}]}))
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                load_packs(path)


class EvaluationAndLogTests(unittest.TestCase):
    def test_image_file_time_check(self):
        result = {"evidence_kind": "image", "integrity": {"status": "verified"},
                  "tool_runs": [{"tool": "sleuthkit", "status": "success"}],
                  "findings": [artifact("sleuthkit", "file_time", "NOTE.TXT", {"macb": "m..."}, "2026-09-20T00:00:00+00:00")]}
        expected = {"image_file_time": {"file": "NOTE.TXT", "date": "2026-09-20"}}
        self.assertEqual(evaluate(result, expected)["checks"][1]["status"], "pass")
        expected["image_file_time"]["date"] = "2026-09-21"
        self.assertEqual(evaluate(result, expected)["checks"][1]["status"], "fail")
        result["evidence_kind"] = "directory"
        self.assertEqual(evaluate(result, expected)["checks"][1]["status"], "skipped")

    def test_step_logs_reads_case_logs_only(self):
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder) / "case"
            (case / "logs").mkdir(parents=True)
            (case / "logs" / "tool.stderr.txt").write_text("boom: file format error")
            (Path(folder) / "secret.txt").write_text("outside")
            run = {"steps": [{"step": "tool", "status": "failed", "exit_code": 1, "command": ["tool", "-x"],
                              "stderr_log": "logs/tool.stderr.txt", "stdout_log": "../secret.txt"}]}
            [step] = step_logs(case, run)
            self.assertEqual(step["stderr"], "boom: file format error")
            self.assertIn("outside the case logs folder", step["stdout"])
            self.assertEqual(step["command"], "tool -x")


class BenchmarkTests(unittest.TestCase):
    def test_benchmark_runs_scores_and_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            report = run_benchmark(Path(folder) / "bench", runs=2, config={"commands": {}})
            extraction = report["summary"]["extraction"]
            self.assertEqual(len(extraction["verdicts"]), 2)
            self.assertNotIn("fail", extraction["verdicts"])
            self.assertTrue(extraction["consistent_findings"])
            self.assertIn("integrity", extraction["checks"])
            self.assertTrue((Path(folder) / "bench" / "benchmark.md").is_file())
            self.assertIn("| extraction |", markdown(report))
            with self.assertRaisesRegex(ValueError, "already exists"):
                run_benchmark(Path(folder) / "bench", runs=1, config={})


class DesktopSmokeTests(unittest.TestCase):
    def test_tool_screen_and_log_viewer_render(self):
        try:
            import tkinter as tk
            root = tk.Tk()
        except Exception as exc:  # no display available
            self.skipTest(f"Tk unavailable: {exc}")
        root.withdraw()
        try:
            from mobile_df.desktop import DesktopApp
            with tempfile.TemporaryDirectory() as folder:
                root_path = Path(folder)
                evidence = root_path / "evidence"
                evidence.mkdir()
                (evidence / "a.txt").write_text("hello")
                case = root_path / "cases" / "c1"
                analyze(evidence, case, tools=["sqlite"], config={})
                app = DesktopApp(root, data_dir=root_path / "cases", settings_path=root_path / "settings.json")
                app.show_tools()
                app.show_case_review(case)
                result = json.loads((case / "results.json").read_text(encoding="utf-8"))
                run = next(r for r in result["tool_runs"] if r["tool"] == "sqlite")
                app._show_logs(case, run)
                root.update_idletasks()
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
