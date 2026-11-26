"""ALEAPP report parsing on real-phone output: very large cells and unreadable reports."""
import sys
import tempfile
import unittest
from pathlib import Path

from mobile_df.demo import create_demo
from mobile_df.pipeline import analyze

# Stands in for ALEAPP: writes TSV reports into the folder given after -o.
FAKE_ALEAPP = r'''
import sys
from pathlib import Path
out = Path(sys.argv[sys.argv.index("-o") + 1]) / "ALEAPP_Output" / "_TSV Exports"
out.mkdir(parents=True)
(out / "SMS Messages.tsv").write_text("Date\tMessage\tSource\n2020-10-04 14:34:18\tReceived.\tdata/mmssms.db\n"
                                      "2020-10-04 14:32:00\tWatching a film\tdata/mmssms.db\n", encoding="utf-8")
# Browser local storage and fitness JSON reports hold single cells far above csv's default 131,072 limit.
(out / "Browser Data - Localstorage.tsv").write_text("Key\tValue\nstate\t" + "x" * 300000 + "\n", encoding="utf-8")
if "--with-unreadable" in sys.argv:
    (out / "Broken report.tsv").mkdir()   # opening it fails, like a report the parser cannot read
'''


class AleappReportTests(unittest.TestCase):
    def run_case(self, root, *extra):
        script = root / "fake_aleapp.py"
        script.write_text(FAKE_ALEAPP, encoding="utf-8")
        evidence = create_demo(root / "fixture")["evidence"]
        config = {"commands": {"aleapp": [sys.executable, str(script), *extra]}}
        result = analyze(evidence, root / "case", tools=["aleapp"], config=config)
        run = next(r for r in result["tool_runs"] if r["tool"] == "aleapp")
        return run, [f for f in result["findings"] if f["source"] == "aleapp"]

    def test_cells_over_the_csv_default_limit_are_read(self):
        with tempfile.TemporaryDirectory() as folder:
            run, findings = self.run_case(Path(folder))
            self.assertEqual(run["status"], "success", run.get("reason"))
            self.assertEqual(run["findings_count"], 3)
            storage = next(f for f in findings if f["detail"].get("Key") == "state")
            self.assertEqual(len(storage["detail"]["Value"]), 300000)

    def test_one_unreadable_report_keeps_the_others_and_is_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            run, findings = self.run_case(Path(folder), "--with-unreadable")
            self.assertEqual(run["status"], "partial")
            self.assertIn("Could not read 1 of 3 ALEAPP reports: Broken report", run["reason"])
            kinds = [f["kind"] for f in findings]
            self.assertEqual(kinds.count("android_artifact"), 3, "the other reports are still parsed")
            error = next(f for f in findings if f["kind"] == "analysis_error")
            self.assertEqual(error["severity"], "warning")
            self.assertIn("Broken report.tsv", error["path"])


if __name__ == "__main__":
    unittest.main()
