"""Plain-language case summary and findings grouped by category."""
import json
import tempfile
import unittest
from pathlib import Path

from mobile_df.demo import create_demo
from mobile_df.pipeline import analyze
from mobile_df.summary import (CATEGORIES, case_overview, categorize, filter_category, group_findings,
                               plain_status)


def aleapp(report):
    return {"source": "aleapp", "kind": "android_artifact", "path": "data/x.db", "detail": {},
            "provenance": {"output": f"tools/aleapp/ALEAPP_Output/_TSV Exports/{report}.tsv", "row": 2}}


def finding(source, kind, path="", **detail):
    return {"source": source, "kind": kind, "path": path, "detail": detail}


class CategoryTests(unittest.TestCase):
    def test_aleapp_reports(self):
        expected = {
            "SMS Messages": "messages", "Facebook Messenger - Chats (threads_db2)": "messages",
            "Gmail - App Emails": "messages", "Line - Call Logs": "calls", "Call logs ": "calls",
            "Facebook Messenger - Contacts (threads_db2)": "contacts", "Telegram - Users": "contacts",
            "Google Maps Directions": "locations", "Chrome Browser Cache": "web", "Keyword Search Terms": "web",
            "Google Photos - Local Media": "media", "Accounts_ce": "accounts", "Netstats": "apps",
            "InstalledappsLibrary": "apps", "Settings Global": "device", "Bluetooth Connections": "device",
            "Emulated Storage Metadata - Files (Legacy)": "files", "Something new from ALEAPP": "apps",
        }
        for report, category in expected.items():
            self.assertEqual(categorize(aleapp(report)), category, report)

    def test_other_tools(self):
        cases = [
            (finding("sqlite", "database_row", "data/data/com.android.providers.telephony/databases/mmssms.db",
                     table="sms"), "messages"),
            (finding("sqlite", "database_row", "a/calllog.db", table="calls"), "calls"),
            (finding("sqlite", "database_row", "app_chrome/Default/History", table="urls"), "web"),
            (finding("sqlite", "database_row", "some/app.db", table="messages"), "messages"),
            (finding("sqlite", "database_row", "some/app.db", table="prefs"), "files"),
            (finding("sqlite", "database_table", "a/mmssms.db", table="sms"), "files"),
            (finding("exiftool", "metadata", "DCIM/a.jpg", **{"File:MIMEType": "image/jpeg"}), "media"),
            (finding("exiftool", "metadata", "doc.pdf", **{"File:MIMEType": "application/pdf"}), "files"),
            (finding("plaso", "timeline_event", data_type="msiecf:url"), "web"),
            (finding("plaso", "timeline_event", data_type="windows:lnk:link"), "apps"),
            (finding("plaso", "timeline_event", data_type="pe_coff:file"), "files"),
            (finding("plaso", "timeline_event", data_type="fs:stat"), "files"),
            (finding("mvt", "mobile_artifact", "tool-output:tools/mvt/sms.json"), "messages"),
            (finding("yara", "rule_match", rule="X"), "leads"),
            (finding("mvt", "indicator", module="sms"), "leads"),
            (finding("sleuthkit", "timestamp_anomaly"), "leads"),
            (finding("sleuthkit", "file_time"), "files"),
            (finding("sqlite", "analysis_error", error="bad"), "problems"),
            (finding("inventory", "file", "image.E01"), "evidence"),
        ]
        for item, category in cases:
            self.assertEqual(categorize(item), category, item)

    def test_every_finding_gets_exactly_one_known_category(self):
        items = [aleapp("SMS Messages"), finding("sqlite", "database_row", "x.db"), finding("unknown", "thing")]
        groups = group_findings(items)
        self.assertEqual(sum(len(v) for v in groups.values()), len(items))
        self.assertLessEqual(set(groups), {key for key, _, _ in CATEGORIES})
        self.assertEqual(filter_category(items, "messages"), [items[0]])
        self.assertEqual(filter_category(items, ""), items)

    def test_plain_status(self):
        self.assertEqual(plain_status({"status": "success"}), "Worked")
        self.assertEqual(plain_status({"status": "partial", "reason": "7 files encrypted"}),
                         "Worked, but not everything could be read. 7 files encrypted")
        self.assertEqual(plain_status({"status": "not_applicable", "reason": "Needs a disk image"}),
                         "Not used for this kind of evidence. Needs a disk image")
        self.assertEqual(plain_status({"status": "unavailable", "reason": "x"}), "Not installed on this computer")


class OverviewTests(unittest.TestCase):
    def test_demo_case_overview(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = create_demo(root / "fixture")["evidence"]
            result = analyze(evidence, root / "case", tools=["sqlite", "exiftool", "plaso"],
                             config={"commands": {"plaso": ["Z:/missing/log2timeline.exe"],
                                                  "exiftool": ["Z:/missing/exiftool.exe"]}})
            overview = case_overview(result)
            labels = {c["key"]: c["count"] for c in overview["categories"]}
            self.assertGreater(labels.get("messages", 0), 0, labels)
            self.assertGreater(labels.get("web", 0), 0, labels)
            self.assertEqual(labels.get("evidence"), len(result["inventory"]))
            self.assertIn("1 tool produced results", overview["headline"])
            self.assertIn("The evidence was not changed", overview["headline"])
            self.assertEqual(overview["integrity"], "verified")
            tools = {t["tool"]: t["plain"] for t in overview["tools"]}
            self.assertEqual(tools["sqlite"], "Worked")
            self.assertEqual(tools["plaso"], "Not installed on this computer")
            self.assertEqual(overview["activity_range"], ("2026-09-20", "2026-09-20"))
            self.assertEqual(overview["busiest_days"][0][0], "2026-09-20")

    def test_attention_lists_problems_and_ignores_times_after_analysis(self):
        result = {
            "started_utc": "2026-01-01T00:00:00+00:00", "completed_utc": "2026-01-01T00:10:05+00:00",
            "evidence_kind": "directory", "integrity": {"status": "changed"},
            "warnings": ["Something odd"],
            "tool_runs": [{"tool": "sqlite", "status": "failed", "reason": "Crashed"},
                          {"tool": "aleapp", "status": "partial", "reason": "Finding limit reached"}],
            "findings": [aleapp("SMS Messages") | {"timestamp": "2019-04-05T10:00:00+00:00"},
                         aleapp("SMS Messages") | {"timestamp": "2026-02-01T00:00:00+00:00"},
                         finding("yara", "rule_match", rule="X")],
        }
        overview = case_overview(result)
        self.assertIn("10 min 5 s", overview["headline"])
        self.assertIn("1 did not work", overview["headline"])
        self.assertEqual(overview["activity_range"], ("2019-04-05", "2019-04-05"), "later time is the app's own copy")
        joined = "\n".join(overview["attention"])
        for text in ("integrity is changed", "sqlite: Did not work. Crashed", "Finding limit reached",
                     "1 lead(s) to check", "Something odd"):
            self.assertIn(text, joined)


class DesktopSummaryTests(unittest.TestCase):
    def test_summary_tab_first_and_category_click_filters_findings(self):
        try:
            import tkinter as tk
            root = tk.Tk()
        except Exception as exc:  # no display available
            self.skipTest(f"Tk unavailable: {exc}")
        root.withdraw()
        try:
            from tkinter import ttk
            from mobile_df.desktop import DesktopApp
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder)
                evidence = create_demo(path / "fixture")["evidence"]
                case = path / "cases" / "c1"
                analyze(evidence, case, tools=["sqlite"], config={})
                app = DesktopApp(root, data_dir=path / "cases", settings_path=path / "settings.json")
                app.show_case_review(case)
                root.update_idletasks()
                notebook = next(w for w in _walk(app.content) if isinstance(w, ttk.Notebook))
                names = [notebook.tab(t, "text") for t in notebook.tabs()]
                self.assertEqual(names[:2], ["SUMMARY", "FINDINGS"])
                self.assertEqual(notebook.index("current"), 0, "the summary opens first")
                messages = next(w for w in _walk(notebook) if isinstance(w, tk.Label) and w.cget("text") == "Messages")
                messages.event_generate("<Button-1>")
                root.update_idletasks()
                self.assertEqual(notebook.index("current"), 1)
                table = next(w for w in _walk(notebook) if isinstance(w, ttk.Treeview) and "category" in w["columns"])
                rows = [table.item(i, "values")[0] for i in table.get_children()]
                self.assertTrue(rows)
                self.assertEqual(set(rows), {"Messages"})
                json.dumps(rows)
        finally:
            root.destroy()


def _walk(widget):
    for child in widget.winfo_children():
        yield child
        yield from _walk(child)


if __name__ == "__main__":
    unittest.main()
