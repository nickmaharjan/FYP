import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from mobile_df.case_library import archive_case, delete_case, list_archived, list_cases, restore_case
from mobile_df.demo import create_demo
from mobile_df.pipeline import analyze
from mobile_df.progress import RUN_ORDER, ProgressModel
from mobile_df.settings import DEFAULTS, load_settings, save_settings, selected_tools


class SettingsTests(unittest.TestCase):
    def test_save_and_load_round_trip(self):
        with tempfile.TemporaryDirectory() as folder:
            rules = Path(folder) / "rules.yar"
            rules.write_text("rule x { condition: false }")
            path = Path(folder) / "nested" / "settings.json"
            saved = save_settings(path, {**DEFAULTS, "timeout": "45", "yara_rules": str(rules),
                                         "default_tools": ["yara", "sqlite"]})
            self.assertEqual(saved["timeout"], 45)
            self.assertEqual(saved["default_tools"], ["sqlite", "yara"])
            self.assertEqual(load_settings(path), saved)

    def test_invalid_values_are_rejected_and_nothing_written(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "settings.json"
            with self.assertRaises(ValueError) as error:
                save_settings(path, {**DEFAULTS, "timeout": "0", "max_rows": "abc", "yara_rules": "missing.yar",
                                     "data_dir": " ", "default_tools": ["nope"]})
            message = str(error.exception)
            for text in ("Timeout", "Max rows", "YARA rules", "data folder", "Unknown tools"):
                self.assertIn(text, message)
            self.assertFalse(path.exists())

    def test_load_tolerates_missing_corrupt_and_partly_invalid_files(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "settings.json"
            self.assertEqual(load_settings(path), DEFAULTS)
            path.write_text("{broken")
            self.assertEqual(load_settings(path), DEFAULTS)
            path.write_text(json.dumps({"timeout": -5, "max_rows": 20, "extra": 1}))
            loaded = load_settings(path)
            self.assertEqual((loaded["timeout"], loaded["max_rows"]), (DEFAULTS["timeout"], 20))
            self.assertNotIn("extra", loaded)

    def test_selected_tools_respects_installation_and_defaults(self):
        availability = {"sqlite": {"available": True}, "yara": {"available": True}, "plaso": {"available": False}}
        self.assertEqual(selected_tools(DEFAULTS, availability), ["sqlite", "yara"])
        self.assertEqual(selected_tools({**DEFAULTS, "default_tools": ["yara", "plaso"]}, availability), ["yara"])


class ProgressTests(unittest.TestCase):
    def test_model_tracks_tools_and_infers_skipped(self):
        now = [100.0]
        model = ProgressModel(["sqlite", "yara", "sleuthkit"], clock=lambda: now[0])
        self.assertEqual(model.tools, [t for t in RUN_ORDER if t in {"sqlite", "yara", "sleuthkit"}])
        for message in ("Hashing original evidence", "Creating and verifying working copy", "Running sqlite"):
            model.update(message)
        self.assertEqual(model.states["sqlite"], "running")
        self.assertEqual(model.states["sleuthkit"], "skipped", "earlier tool that never started is skipped")
        model.update("sqlite: success (12 findings)")
        self.assertEqual((model.states["sqlite"], model.findings["sqlite"]), ("success", 12))
        before = model.fraction
        model.update("Verifying original evidence after analysis")
        self.assertEqual(model.states["yara"], "skipped")
        self.assertGreater(model.fraction, before)
        self.assertLess(model.fraction, 1.0)
        model.update("Case completed_with_warnings; report saved")
        self.assertTrue(model.finished)
        self.assertEqual(model.fraction, 1.0)
        now[0] = 165.0
        self.assertEqual(model.elapsed_seconds, 65)

    def test_model_matches_real_pipeline_messages(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = create_demo(root / "fixture")["evidence"]
            model = ProgressModel(["sqlite", "sleuthkit"])
            result = analyze(evidence, root / "case", tools=["sqlite", "sleuthkit"], config={}, progress=model.update)
            self.assertTrue(model.finished)
            runs = {run["tool"]: run for run in result["tool_runs"]}
            self.assertEqual(model.states["sqlite"], runs["sqlite"]["status"])
            self.assertEqual(model.findings["sqlite"], runs["sqlite"]["findings_count"])
            self.assertEqual(model.states["sleuthkit"], "skipped")


class ArchiveTests(unittest.TestCase):
    def make_case(self, root, name="case1"):
        evidence = create_demo(root / f"fixture-{name}")["evidence"]
        analyze(evidence, root / "cases" / name, f"CASE-{name}", tools=["sqlite"], config={})
        return root / "cases" / name, evidence

    def test_archive_restore_and_delete(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            data = root / "cases"
            case, evidence = self.make_case(root)
            archived = archive_case(data, case)
            self.assertEqual(list_cases(data), [])
            self.assertEqual([c["case_id"] for c in list_archived(data)], ["CASE-case1"])
            restored = restore_case(data, archived)
            self.assertEqual([c["case_id"] for c in list_cases(data)], ["CASE-case1"])
            # Make one working copy read-only, as Windows evidence copies can be.
            copy = next(p for p in restored.rglob("*") if p.is_file() and "working" in p.parts)
            os.chmod(copy, stat.S_IREAD)
            delete_case(data, restored)
            self.assertFalse(restored.exists())
            self.assertTrue(evidence.is_dir(), "original evidence untouched")
            self.assertEqual(list_cases(data), [])

    def test_delete_from_archive_and_refuses_paths_outside_library(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            data = root / "cases"
            case, evidence = self.make_case(root)
            for bad in (evidence, root, data, data / "missing", data / ".." / "cases" / ".."):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    delete_case(data, bad)
            (data / "plain-folder").mkdir()
            with self.assertRaises(ValueError):
                archive_case(data, data / "plain-folder")
            archived = archive_case(data, case)
            self.make_case(root, "case1-again")
            delete_case(data, archived)
            self.assertEqual(list_archived(data), [])

    def test_archive_does_not_overwrite_existing_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            data = root / "cases"
            case, _ = self.make_case(root)
            (data / "_archive" / "case1").mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "already exists"):
                archive_case(data, case)
            self.assertTrue(case.is_dir())


if __name__ == "__main__":
    unittest.main()
