import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from mobile_df.cli import main
from mobile_df.core import artifact, correlate
from mobile_df.demo import create_demo
from mobile_df.evaluation import evaluate, evaluate_case
from mobile_df.pipeline import analyze

URL = "https://training-ioc.example/check"


def synthetic_case(kind="directory", **statuses):
    """A hand-built result covering every tool, so checks run without installed binaries."""
    findings = [
        artifact("sqlite", "database_table", "mmssms.db", {"table": "sms"}),
        artifact("sqlite", "database_table", "History", {"table": "urls"}),
        artifact("sqlite", "database_row", "mmssms.db", {"table": "sms", "values": {"body": URL}}),
        artifact("mvt", "mobile_artifact", "tool-output:tools/mvt/sms.json", {"body": URL},
                 provenance={"output": "tools/mvt/sms.json", "record": 1}),
        artifact("yara", "rule_match", "training-note.txt", {"rule": "DFIR_Demo_Marker"}),
        artifact("exiftool", "metadata", "media/0/DCIM/training.png", {"File:FileType": "PNG"}),
        artifact("sleuthkit", "filesystem_entry", "NOTE.TXT", {"entry": "r/r 4:\tNOTE.TXT"}),
    ]
    tools = ("sqlite", "yara", "exiftool", "aleapp", "mvt", "sleuthkit")
    runs = [{"tool": t, "status": statuses.get(t, "success")} for t in tools]
    return {"case_id": "T", "status": "completed", "evidence_kind": kind, "tool_runs": runs,
            "integrity": {"status": "verified"}, "findings": findings, "correlations": correlate(findings)}


EXPECTED = {"description": "test", "sqlite_sms_rows": 1, "mvt_sms_rows": 1, "yara_rule": "DFIR_Demo_Marker",
            "shared_url": URL, "media_files": 1, "image_file": "NOTE.TXT", "sqlite_database_files": 2}


def by_id(evaluation):
    return {c["id"]: c for c in evaluation["checks"]}


class EvaluationTests(unittest.TestCase):
    def test_all_expectations_pass_for_matching_case(self):
        result = evaluate(synthetic_case(), EXPECTED)
        checks = by_id(result)
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(checks["image_file"]["status"], "skipped")  # directory case
        self.assertTrue(all(c["status"] == "pass" for k, c in checks.items() if k != "image_file"), checks)
        self.assertEqual(result["score"], 1.0)

    def test_image_check_runs_for_image_cases(self):
        checks = by_id(evaluate(synthetic_case(kind="image"), {"image_file": "note.txt"}))
        self.assertEqual(checks["image_file"]["status"], "pass")

    def test_mismatch_fails_and_names_observed_value(self):
        case = synthetic_case()
        case["findings"] = [f for f in case["findings"] if f["kind"] != "database_row"]
        result = evaluate(case, EXPECTED)
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(by_id(result)["sqlite_sms_rows"]["observed"], 0)

    def test_unavailable_tool_is_skipped_not_failed(self):
        result = evaluate(synthetic_case(yara="unavailable", mvt="unavailable"), EXPECTED)
        checks = by_id(result)
        self.assertEqual(checks["yara_rule"]["status"], "skipped")
        self.assertIn("yara unavailable", checks["yara_rule"]["reason"])
        self.assertEqual(checks["mvt_sms_rows"]["status"], "skipped")
        self.assertEqual(checks["shared_url"]["status"], "pass")  # at least two URL-capable tools still ran
        self.assertEqual(result["verdict"], "pass")

    def test_changed_evidence_and_unknown_keys_are_visible(self):
        case = synthetic_case()
        case["integrity"]["status"] = "changed"
        result = evaluate(case, {"new_metric": 3})
        checks = by_id(result)
        self.assertEqual(checks["integrity"]["status"], "fail")
        self.assertEqual(checks["new_metric"]["status"], "unsupported")
        self.assertEqual(result["verdict"], "fail")

    def test_integrity_alone_is_inconclusive(self):
        result = evaluate(synthetic_case(sqlite="unavailable"), {"sqlite_sms_rows": 1})
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["summary"]["skipped"], 1)


class DemoEvaluationTests(unittest.TestCase):
    def test_real_sqlite_run_against_demo_expectations(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture = create_demo(root / "fixture")
            analyze(**fixture, output=root / "case", tools=["sqlite"], config={})
            result = evaluate_case(root / "case", root / "fixture/expected.json")
            checks = by_id(result)
            self.assertEqual(result["verdict"], "pass", checks)
            self.assertEqual(checks["sqlite_sms_rows"]["status"], "pass")
            self.assertEqual(checks["sqlite_database_files"]["status"], "pass")
            self.assertEqual(checks["yara_rule"]["status"], "skipped")

            out = root / "evaluation.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["evaluate", str(root / "case"), "--expected", str(root / "fixture/expected.json"),
                             "--output", str(out)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["verdict"], "pass")
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                main(["evaluate", str(root / "case"), "--expected", str(root / "fixture/expected.json"),
                      "--output", str(out)])


if __name__ == "__main__":
    unittest.main()
