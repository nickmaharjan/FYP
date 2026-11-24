"""Readable one-line text for findings, and the enriched data used by the HTML report and dashboard."""
import csv
import json
import tempfile
import unittest
from pathlib import Path

from mobile_df.case_library import export_findings_csv
from mobile_df.demo import create_demo
from mobile_df.pipeline import analyze
from mobile_df.report import render_report
from mobile_df.summary import MAX_TEXT, describe, enrich


def aleapp(report, **values):
    return {"source": "aleapp", "kind": "android_artifact", "path": "x", "detail": values,
            "provenance": {"output": f"tools/aleapp/_TSV Exports/{report}.tsv"}}


def row(path, table, **values):
    return {"source": "sqlite", "kind": "database_row", "path": path, "detail": {"table": table, "values": values}}


class DescribeTests(unittest.TestCase):
    def test_messages_calls_and_web(self):
        self.assertEqual(describe(row("a/mmssms.db", "sms", address="+1555", body="Hi\nthere", type=1)),
                         "Received SMS from +1555: “Hi there”")
        self.assertEqual(describe(row("a/mmssms.db", "sms", address="244", body="Code", type=2)),
                         "Sent SMS to 244: “Code”")
        self.assertEqual(describe(row("a/calllog.db", "calls", number="+1984", name=None, type=3, duration=0)),
                         "Missed call with +1984")
        self.assertEqual(describe(row("a/calllog.db", "calls", number="+1910", name="Josh", type=2, duration=42)),
                         "Outgoing call to +1910 (Josh), 42 s")
        self.assertEqual(describe(row("Default/History", "urls", url="https://a.example", title="A")),
                         "Visited A — https://a.example")

    def test_aleapp_rows_pick_useful_columns_and_strip_markup(self):
        text = describe(aleapp("Call logs ", **{"Call Date": "2019-02-22", "Partner": "+1984",
                                                "Type": 'Missed <i data-feather="phone-missed"></i>',
                                                "Duration in Secs": "0", "Source File": "x.db"}))
        self.assertEqual(text, "Call logs: Partner: +1984 · Type: Missed")
        text = describe(aleapp("Accounts_ce", **{"Account Type": "com.google", "Account Name": "a@example.com",
                                                 "Password": "secret-token"}))
        self.assertIn("Account Name: a@example.com", text)
        self.assertNotIn("secret-token", text, "tokens are not repeated in the readable line")

    def test_files_plaso_leads_and_problems(self):
        self.assertEqual(describe({"source": "sleuthkit", "kind": "filesystem_entry", "path": "Users/a.txt",
                                   "detail": {"mode": "r/rrw", "size": 1234, "deleted": True}}),
                         "Deleted file Users/a.txt, 1,234 bytes")
        self.assertEqual(describe({"source": "sleuthkit", "kind": "file_time", "path": "a.txt",
                                   "detail": {"macb": "m..b"}}), "File modified, created: a.txt")
        self.assertEqual(describe({"source": "plaso", "kind": "timeline_event", "path": "",
                                   "detail": {"timestamp_desc": "Last Visited Time", "message": "Location: http://x"}}),
                         "Last Visited Time: Location: http://x")
        self.assertIn("YARA rule DFIR matched note.txt",
                      describe({"source": "yara", "kind": "rule_match", "path": "d/note.txt", "detail": {"rule": "DFIR"}}))
        self.assertEqual(describe({"source": "sqlite", "kind": "analysis_error", "path": "d/History",
                                   "detail": {"table": "meta", "error": "bad"}}), "Could not read History table meta: bad")
        self.assertEqual(describe({"source": "exiftool", "kind": "metadata", "path": "DCIM/a.jpg",
                                   "detail": {"File:FileType": "JPEG", "EXIF:DateTimeOriginal": "2019:04:05 10:00:00",
                                              "EXIF:Make": "Google", "EXIF:Model": "Pixel 3"}}),
                         "JPEG a.jpg, taken 2019:04:05 10:00:00, camera Google Pixel 3")

    def test_unknown_shapes_and_length_limit(self):
        self.assertTrue(describe({"source": "new", "kind": "thing", "path": "p/q.bin", "detail": {"k": "v"}}).startswith("q.bin: k: v"))
        self.assertLessEqual(len(describe(row("a/mmssms.db", "sms", address="1", body="x" * 5000, type=1))), MAX_TEXT)


class EnrichedOutputTests(unittest.TestCase):
    def test_report_and_csv_carry_categories_and_text_but_results_json_is_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = create_demo(root / "fixture")["evidence"]
            result = analyze(evidence, root / "case", tools=["sqlite"], config={})
            saved = json.loads((root / "case/results.json").read_text(encoding="utf-8"))
            self.assertNotIn("overview", saved)
            self.assertNotIn("text", saved["findings"][0])

            data = enrich(result)
            self.assertIn("headline", data["overview"])
            sms = next(f for f in data["findings"] if f["detail"].get("table") == "sms" and f["kind"] == "database_row")
            self.assertEqual((sms["category"], sms["category_label"]), ("messages", "Messages"))
            self.assertTrue(sms["text"].startswith("Received SMS from +15550100001"))
            self.assertTrue(all("text" in f for f in data["timeline"]))
            self.assertNotIn("text", result["findings"][0], "enrich returns a copy")

            page = (root / "case/report.html").read_text(encoding="utf-8")
            self.assertIn('"category_label"', page)
            self.assertIn("Received SMS from +15550100001", page)
            self.assertIn("function summaryView", page)
            self.assertNotIn("<script>alert", render_report({**result, "case_id": "<script>alert(1)</script>"}))

            path = export_findings_csv([sms], root / "out.csv")
            with path.open(encoding="utf-8-sig", newline="") as stream:
                header, first = list(csv.reader(stream))[:2]
            self.assertEqual(header[-2:], ["category", "what"])
            self.assertEqual(first[-2], "Messages")
            self.assertTrue(first[-1].startswith("Received SMS"))


if __name__ == "__main__":
    unittest.main()
