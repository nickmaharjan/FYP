"""Split disk images: every segment is found, hashed, copied and verified; missing segments are explained."""
import sys
import tempfile
import unittest
from pathlib import Path

from mobile_df.config import doctor, load_config
from mobile_df.demo import create_fat12
from mobile_df.evidence import ewf_end_marker, image_segments
from mobile_df.pipeline import analyze


def ewf_segment(path, marker):
    """Enough of an EnCase segment for discovery: a body ending in a 76-byte section descriptor."""
    path.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 200 + marker.ljust(16, b"\x00") + b"\x00" * 60)
    return path


class SegmentDiscoveryTests(unittest.TestCase):
    def test_ewf_complete_incomplete_and_wrong_start(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ewf_segment(root / "disk.E01", b"next")
            ewf_segment(root / "disk.E02", b"done")
            segments, problem = image_segments(root / "disk.E01")
            self.assertEqual([p.name for p in segments], ["disk.E01", "disk.E02"])
            self.assertIsNone(problem)
            self.assertEqual((ewf_end_marker(root / "disk.E01"), ewf_end_marker(root / "disk.E02")), ("next", "done"))
            (root / "disk.E02").unlink()
            segments, problem = image_segments(root / "disk.E01")
            self.assertEqual(len(segments), 1)
            self.assertIn("disk.E02 is missing", problem)
            ewf_segment(root / "disk.E02", b"done")
            _, problem = image_segments(root / "disk.E02")
            self.assertIn("choose disk.E01", problem)
            self.assertEqual(image_segments(root / "single.dd"), ([root / "single.dd"], None))

    def test_raw_split_sequence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for n in (1, 2, 3):
                (root / f"disk.{n:03d}").write_bytes(b"x")
            (root / "disk.005").write_bytes(b"gap; not part of the run")
            segments, problem = image_segments(root / "disk.001")
            self.assertEqual([p.name for p in segments], ["disk.001", "disk.002", "disk.003"])
            self.assertIsNone(problem, "raw splits carry no end marker, so a gap cannot be detected")


class SplitPipelineTests(unittest.TestCase):
    def split_fat12(self, root):
        image = root / "whole.img"
        create_fat12(image)
        data = image.read_bytes()
        middle = len(data) // 2
        (root / "split").mkdir()
        (root / "split" / "card.001").write_bytes(data[:middle])
        (root / "split" / "card.002").write_bytes(data[middle:])
        return root / "split" / "card.001"

    def test_every_segment_is_hashed_copied_and_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first = self.split_fat12(root)
            result = analyze(first, root / "case", tools=["sqlite"], config={}, kind="image")
            self.assertEqual([item["path"] for item in result["inventory"]], ["card.001", "card.002"])
            self.assertEqual(result["parameters"]["image_segments"], ["card.001", "card.002"])
            self.assertTrue((root / "case/working/card.002").is_file())
            self.assertEqual(result["integrity"]["status"], "verified")

    def test_real_sleuthkit_reads_raw_split(self):
        config = load_config()
        if not (doctor(config)["sleuthkit"]["available"]):
            self.skipTest("The Sleuth Kit is not installed")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first = self.split_fat12(root)
            result = analyze(first, root / "case", tools=["sleuthkit"], config=config, kind="image")
            run = next(r for r in result["tool_runs"] if r["tool"] == "sleuthkit")
            self.assertEqual(run["status"], "success", run)
            self.assertIn("NOTE.TXT", {f["path"] for f in result["findings"] if f["kind"] == "filesystem_entry"})
            self.assertTrue((root / "case/tools/recovered/NOTE.TXT").is_file())

    def test_missing_segment_is_the_reason_given(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first = ewf_segment(root / "laptop.E01", b"next")
            fake = root / "fake_fls.py"
            fake.write_text("import sys\nsys.stderr.write('Error reading image file (ewf_image_read)')\nsys.exit(1)\n")
            config = {"commands": {"sleuthkit": [sys.executable, str(fake)]}}
            result = analyze(first, root / "case", tools=["sleuthkit"], config=config)
            run = next(r for r in result["tool_runs"] if r["tool"] == "sleuthkit")
            self.assertEqual(run["status"], "failed")
            self.assertIn("laptop.E02 is missing", run["reason"])
            self.assertTrue(any("laptop.E02 is missing" in w for w in result["warnings"]))
            self.assertEqual(result["status"], "completed_with_warnings")


if __name__ == "__main__":
    unittest.main()
