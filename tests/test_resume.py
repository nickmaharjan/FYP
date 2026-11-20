import json
import shutil
import tempfile
import unittest
from pathlib import Path

from mobile_df.case_library import list_cases, rerun_options
from mobile_df.config import doctor
from mobile_df.demo import create_demo
from mobile_df.pipeline import analyze


class Interrupted(BaseException):
    """Like closing the app or losing power: not an ordinary error the pipeline can record."""


def interrupt_at(trigger):
    def progress(message):
        if message == trigger:
            raise Interrupted()
    return progress


class ResumeTests(unittest.TestCase):
    def interrupted_case(self, root, **options):
        fixture = create_demo(root / "fixture")
        output = root / "cases" / "interrupted"
        with self.assertRaises(Interrupted):
            analyze(fixture["evidence"], output, "CASE-RESUME", config={}, progress=interrupt_at("Running sqlite"),
                    tools=["sqlite", "yara"], yara_rules=fixture["yara_rules"], timeout=77, max_rows=12, **options)
        return fixture, output

    def test_interrupted_case_records_how_to_rerun_and_rerun_completes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture, output = self.interrupted_case(root)
            self.assertFalse((output / "results.json").exists())
            [summary] = list_cases(root / "cases")
            self.assertEqual((summary["status"], summary["evidence"]), ("incomplete", str(fixture["evidence"])))
            self.assertTrue(summary["started_utc"])

            options = rerun_options(output)
            self.assertEqual(options["case_id"], "CASE-RESUME")
            self.assertEqual(options["tools"], ["sqlite", "yara"])
            self.assertEqual((options["timeout"], options["max_rows"]), (77, 12))
            self.assertEqual(Path(options["yara_rules"]), fixture["yara_rules"].resolve())

            result = analyze(output=root / "cases" / "rerun", config={}, **options)
            # yara-python is optional (installed by scripts/setup.ps1). Without it the re-run is
            # still valid but YARA is reported unavailable, so the case ends with warnings.
            yara_ready = doctor({})["yara"]["available"]
            finished = "completed" if yara_ready else "completed_with_warnings"
            self.assertEqual(result["status"], finished)
            self.assertEqual(result["parameters"]["timeout"], 77)
            runs = {run["tool"]: run["status"] for run in result["tool_runs"]}
            self.assertEqual((runs["sqlite"], runs["yara"]), ("success", "success" if yara_ready else "unavailable"))
            statuses = sorted(case["status"] for case in list_cases(root / "cases"))
            self.assertEqual(statuses, sorted([finished, "incomplete"]), "interrupted folder is kept")
            with self.assertRaisesRegex(ValueError, "finished"):
                rerun_options(root / "cases" / "rerun")

    def test_rerun_refuses_missing_inputs_and_old_cases(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture, output = self.interrupted_case(root)
            rules = Path(json.loads((output / "status.json").read_text(encoding="utf-8"))["rerun"]["yara_rules"])
            rules.rename(rules.with_suffix(".moved"))
            with self.assertRaisesRegex(ValueError, "YARA rules"):
                rerun_options(output)
            shutil.rmtree(fixture["evidence"])
            with self.assertRaisesRegex(ValueError, "evidence is no longer available"):
                rerun_options(output)
            old = root / "cases" / "old"
            old.mkdir()
            (old / "status.json").write_text(json.dumps({"case_id": "OLD", "tool_runs": []}))
            with self.assertRaisesRegex(ValueError, "older version"):
                rerun_options(old)
            self.assertEqual(next(c for c in list_cases(root / "cases") if c["case_id"] == "OLD")["evidence"], "")


if __name__ == "__main__":
    unittest.main()
