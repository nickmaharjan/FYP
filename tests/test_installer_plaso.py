"""In-app tool installer, Plaso through Docker, new controlled fixtures and the setup checklist."""
import hashlib
import json
import sys
import tarfile
import tempfile
import threading
import unittest
import zipfile
import zlib
from pathlib import Path

from mobile_df.adapters import container_relative
from mobile_df.config import doctor, load_config
from mobile_df.demo import create_demo
from mobile_df.installer import InstallCancelled, install_pack, pack_status
from mobile_df.pipeline import analyze
from mobile_df.readiness import checklist_complete, setup_checklist


def make_pack(path, files):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return hashlib.sha256(path.read_bytes()).hexdigest()


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.kit = self.root / "kit"
        self.kit.mkdir()
        self.tools = self.root / "tools"
        self.config = self.root / "tools.local.json"
        digest = make_pack(self.kit / "demo.zip", {"bin/demo.exe": b"v2", "bin/tsk_recover.exe": b"x"})
        self.packs = {"demo": {"version": "2.0", "sha256": digest, "binary": "demo/bin/demo.exe",
                               "url": (self.kit / "demo.zip").as_uri()}}

    def tearDown(self):
        self.folder.cleanup()

    def test_install_from_kit_records_state_and_keeps_other_config(self):
        self.config.write_text(json.dumps({"commands": {"aleapp": ["C:/keep/aleapp.exe"]}, "plaso_docker_image": "x:1"}))
        self.assertEqual(pack_status(self.packs, self.tools)["demo"]["action"], "Install")
        summary = install_pack("demo", self.packs, self.tools, self.config, pack_dir=self.kit, offline=True)
        self.assertEqual(summary["version"], "2.0")
        self.assertEqual((self.tools / "demo/bin/demo.exe").read_bytes(), b"v2")
        config = json.loads(self.config.read_text())
        self.assertEqual(config["commands"]["aleapp"], ["C:/keep/aleapp.exe"])
        self.assertEqual(config["plaso_docker_image"], "x:1")
        self.assertTrue(config["commands"]["demo"][0].endswith("demo.exe"))
        self.assertEqual(pack_status(self.packs, self.tools)["demo"]["status"], "up to date")
        self.packs["demo"]["version"] = "3.0"
        self.assertEqual(pack_status(self.packs, self.tools)["demo"]["action"], "Update")
        (self.tools / "demo/bin/demo.exe").unlink()
        self.assertEqual(pack_status(self.packs, self.tools)["demo"]["action"], "Repair")

    def test_download_path_uses_url_and_verifies(self):
        install_pack("demo", self.packs, self.tools, self.config)
        self.assertTrue((self.tools / "demo.zip").is_file())

    def test_checksum_mismatch_installs_nothing(self):
        install_pack("demo", self.packs, self.tools, self.config, pack_dir=self.kit, offline=True)
        make_pack(self.kit / "demo.zip", {"bin/demo.exe": b"evil"})
        (self.tools / "demo.zip").unlink()
        with self.assertRaisesRegex(ValueError, "pinned SHA-256"):
            install_pack("demo", self.packs, self.tools, self.config, pack_dir=self.kit, offline=True)
        self.assertFalse((self.tools / "demo.zip").exists())
        self.assertEqual((self.tools / "demo/bin/demo.exe").read_bytes(), b"v2", "old install kept")

    def test_refusals(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            install_pack("demo", dict(demo=dict(self.packs["demo"], url="http://example.invalid/demo.zip")),
                         self.tools, self.config)
        with self.assertRaisesRegex(ValueError, "Offline install needs"):
            install_pack("demo", self.packs, self.tools, self.config, offline=True)
        with self.assertRaisesRegex(ValueError, "No pinned pack"):
            install_pack("nope", self.packs, self.tools, self.config)
        digest = make_pack(self.kit / "evil.zip", {"../../outside.exe": b"x", "bin/evil.exe": b"x"})
        evil = {"evil": {"version": "1", "sha256": digest, "binary": "evil/bin/evil.exe", "url": "https://x"}}
        with self.assertRaisesRegex(ValueError, "Unsafe path"):
            install_pack("evil", evil, self.tools, self.config, pack_dir=self.kit, offline=True)
        self.assertFalse((self.root / "outside.exe").exists())
        self.assertFalse((self.tools / "evil").exists())

    def test_failed_swap_restores_previous_install(self):
        from unittest import mock
        install_pack("demo", self.packs, self.tools, self.config, pack_dir=self.kit, offline=True)
        real_rename = Path.rename

        def locked(path, target):
            if Path(path).name == "demo.new":
                raise PermissionError("file in use")
            return real_rename(path, target)

        with mock.patch.object(Path, "rename", locked), self.assertRaises(PermissionError):
            install_pack("demo", self.packs, self.tools, self.config, pack_dir=self.kit, offline=True)
        self.assertEqual((self.tools / "demo/bin/demo.exe").read_bytes(), b"v2", "previous install restored")
        self.assertFalse((self.tools / "demo.old").exists())

    def test_cancel_keeps_previous_install(self):
        install_pack("demo", self.packs, self.tools, self.config, pack_dir=self.kit, offline=True)
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(InstallCancelled):
            install_pack("demo", self.packs, self.tools, self.config, pack_dir=self.kit, offline=True, cancel=cancel)
        self.assertEqual((self.tools / "demo/bin/demo.exe").read_bytes(), b"v2")
        self.assertFalse((self.tools / "demo.new").exists())


FAKE_DOCKER = r'''
import json, sys
from pathlib import Path
args = sys.argv[1:]
mounts = {}
i = 0
while i < len(args):
    if args[i] == "-v":
        host, container, mode = args[i + 1].rsplit(":", 2)
        mounts[container] = (host, mode)
        i += 2
    else:
        i += 1
out = Path(mounts["/output"][0])
with (out / "docker-calls.jsonl").open("a") as log:
    log.write(json.dumps({"args": args, "mounts": mounts}) + "\n")
if "log2timeline.py" in args:
    (out / "timeline.plaso").write_text("storage")
else:
    name = Path(json.loads((out / "docker-calls.jsonl").read_text().splitlines()[0])["args"][-1]).name
    event = {"timestamp": 1789905600000000, "filename": f"/evidence/{name}/data/note.txt", "message": "x"}
    (out / "events.jsonl").write_text(json.dumps(event) + "\n")
'''


# A container that outlives the `docker run` client: a marker file stands for the running container,
# which only `docker rm --force <name>` removes, as with real Docker when the client process is killed.
HANGING_DOCKER = r'''
import sys, time
from pathlib import Path
args = sys.argv[1:]
containers = Path(__file__).parent / "containers"
containers.mkdir(exist_ok=True)
if args[:2] == ["rm", "--force"]:
    marker = containers / args[2]
    if not marker.exists():
        print("Error: No such container: " + args[2], file=sys.stderr)
        sys.exit(1)
    marker.unlink()
    print(args[2])
elif args[0] == "run":
    (containers / args[args.index("--name") + 1]).write_text("running")
    time.sleep(120)
'''


class PlasoDockerTests(unittest.TestCase):
    def test_timeout_removes_the_container_it_started(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = root / "extraction"
            evidence.mkdir()
            (evidence / "note.txt").write_text("hello")
            fake = root / "fake_docker.py"
            fake.write_text(HANGING_DOCKER)
            config = {"commands": {"docker": [sys.executable, str(fake)]}, "plaso_docker_image": "log2timeline/plaso:20240308"}
            result = analyze(evidence, root / "case", tools=["plaso"], config=config, timeout=3)
            run = next(r for r in result["tool_runs"] if r["tool"] == "plaso")
            self.assertEqual(run["status"], "timeout")
            [step] = run["steps"]
            name = step["command"][step["command"].index("--name") + 1]
            self.assertTrue(name.startswith("mobile-df-plaso-") and name.endswith("-extract"))
            self.assertEqual(step["container_cleanup"], {"container": name, "removed": True, "output": name})
            self.assertEqual(list((root / "containers").iterdir()), [], "no container is left running")


    def test_docker_runtime_mounts_read_only_without_network_and_maps_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = root / "extraction"
            (evidence / "data").mkdir(parents=True)
            (evidence / "data" / "note.txt").write_text("hello")
            fake = root / "fake_docker.py"
            fake.write_text(FAKE_DOCKER)
            config = {"commands": {"docker": [sys.executable, str(fake)]}, "plaso_docker_image": "log2timeline/plaso:20240308"}
            state = doctor(config)["plaso"]
            self.assertTrue(state["available"])
            self.assertEqual((state["runtime"], state["version"]), ("docker", "20240308"))
            result = analyze(evidence, root / "case", tools=["plaso"], config=config)
            run = next(r for r in result["tool_runs"] if r["tool"] == "plaso")
            self.assertEqual((run["status"], run["findings_count"], run["tool_version"]), ("success", 1, "20240308"))
            [event] = result["timeline"]
            self.assertEqual(event["path"], "data/note.txt")
            self.assertEqual(event["timestamp"], "2026-09-20T12:00:00+00:00")
            calls = [json.loads(line) for line in (root / "case/tools/plaso/docker-calls.jsonl").read_text().splitlines()]
            for call in calls:
                self.assertIn("--network", call["args"])
                self.assertEqual(call["args"][call["args"].index("--network") + 1], "none")
            self.assertEqual(calls[0]["mounts"]["/evidence"][1], "ro")
            self.assertNotIn("/evidence", calls[1]["mounts"], "export never sees evidence")

    def test_config_validation_and_path_mapping(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tools.local.json"
            path.write_text(json.dumps({"plaso_docker_image": "--privileged"}))
            with self.assertRaisesRegex(ValueError, "plaso_docker_image"):
                load_config(path)
        self.assertEqual(container_relative("/evidence/ext/a/b.db", "ext"), "a/b.db")
        self.assertEqual(container_relative("/evidence/img.E01:/Users/x.txt", "img.E01"), "Users/x.txt")
        self.assertEqual(container_relative("/evidence/ext", "ext"), "ext")
        no_docker = {"plaso_docker_image": "x:1", "commands": {"docker": ["Z:/missing/docker.exe"]}}
        self.assertFalse(doctor(no_docker)["plaso"]["available"], "an image alone is not a runtime")


class FixtureTests(unittest.TestCase):
    def test_archive_and_android_backup_fixtures(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "fixture"
            create_demo(root)
            with zipfile.ZipFile(root / "training-extraction.zip") as archive:
                self.assertIn("data/data/com.android.providers.telephony/databases/mmssms.db", archive.namelist())
            data = (root / "training-backup.ab").read_bytes()
            header, body = data.split(b"none\n", 1)
            self.assertEqual(header, b"ANDROID BACKUP\n5\n1\n")
            tar_path = Path(folder) / "backup.tar"
            tar_path.write_bytes(zlib.decompress(body))
            with tarfile.open(tar_path) as archive:
                self.assertEqual(archive.getnames(), ["apps/com.android.providers.telephony/d_f/000000_sms_backup"])
            result = analyze(root / "training-extraction.zip", Path(folder) / "case", tools=["sqlite"], config={})
            self.assertEqual(result["evidence_kind"], "archive")
            self.assertEqual(len({f["path"] for f in result["findings"] if f["kind"] == "database_table"}), 2)


class ChecklistTests(unittest.TestCase):
    def test_checklist_reports_missing_items(self):
        with tempfile.TemporaryDirectory() as folder:
            missing = {name: {"available": False} for name in ("sleuthkit", "exiftool", "aleapp", "yara", "mvt", "plaso")}
            items = {i["key"]: i for i in setup_checklist(missing, {"yara_rules": ""}, Path(folder) / "cases")}
            self.assertFalse(items["tools"]["done"])
            self.assertIn("sleuthkit", items["tools"]["detail"])
            self.assertTrue(items["storage"]["done"])
            self.assertFalse(checklist_complete(items.values()))
            ready = {name: {"available": True} for name in missing}
            rules = Path(folder) / "r.yar"
            rules.write_text("rule x { condition: true }")
            done = setup_checklist(ready, {"yara_rules": str(rules)}, Path(folder) / "cases")
            self.assertTrue(all(item["done"] for item in done))
            self.assertTrue(checklist_complete(done))


if __name__ == "__main__":
    unittest.main()
