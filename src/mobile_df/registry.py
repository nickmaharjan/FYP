"""Tool registry: what each forensic tool is, its licence, the installed version, and pack checksums.

One place answers "which tools do I have, which versions, under which licence, and are the
installed packs the ones this project was tested with?". Pinned packs come from
``tool-packs.json`` (also read by scripts/setup.ps1), so the two never disagree.

    python -m mobile_df.registry            # table of tools, versions and licences
    python -m mobile_df.registry --json     # same, machine-readable
    python -m mobile_df.registry --verify   # check downloaded packs against pinned SHA-256
    python -m mobile_df.registry --notices  # third-party licence notices
"""
import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

from .core import TOOL_NAMES

ROOT = Path(__file__).resolve().parents[2]
PACKS_FILE = ROOT / "tool-packs.json"
TOOLS_DIR = ROOT / ".tools"

TOOLS = {
    "sqlite": {"title": "SQLite", "purpose": "Discover databases and export tables and rows",
               "license": "Public domain", "homepage": "https://sqlite.org/copyright.html",
               "install": "Bundled with Python"},
    "yara": {"title": "YARA (yara-python)", "purpose": "Match investigator-supplied rules against files",
             "license": "BSD-3-Clause (YARA); Apache-2.0 (yara-python)",
             "homepage": "https://github.com/VirusTotal/yara-python", "install": "pip (requirements-forensics.txt)",
             "package": "yara-python"},
    "exiftool": {"title": "ExifTool", "purpose": "Extract media and document metadata",
                 "license": "Same terms as Perl (Artistic License or GPL)", "homepage": "https://exiftool.org/",
                 "install": "Portable pack (setup.ps1)", "version_args": ["-ver"]},
    "aleapp": {"title": "ALEAPP", "purpose": "Parse Android app and system artifacts",
               "license": "MIT", "homepage": "https://github.com/abrignoni/ALEAPP",
               "install": "Portable pack (setup.ps1)"},
    "mvt": {"title": "Mobile Verification Toolkit", "purpose": "Check Android backups and bug reports against indicators",
            "license": "MVT License 1.1 (review before redistribution)", "homepage": "https://github.com/mvt-project/mvt",
            "install": "pip (requirements-forensics.txt)", "package": "mvt"},
    "sleuthkit": {"title": "The Sleuth Kit", "purpose": "List, time and recover files from disk images (raw, E01)",
                  "license": "IBM Public License, CPL and GPL (per component)",
                  "homepage": "https://www.sleuthkit.org/sleuthkit/", "install": "Portable pack (setup.ps1)",
                  "version_args": ["-V"]},
    "plaso": {"title": "Plaso (log2timeline)", "purpose": "Build a super-timeline from many artifact types",
              "license": "Apache-2.0", "homepage": "https://github.com/log2timeline/plaso",
              "install": "Separate Linux environment (see docs/tool-support.md)", "version_args": ["--version"]},
}

_VERSION_CACHE = {}


def load_packs(path=PACKS_FILE):
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    packs = {pack["name"]: pack for pack in data.get("packs", [])}
    for name, pack in packs.items():
        if not re.fullmatch(r"[0-9A-Fa-f]{64}", pack.get("sha256", "")) or not pack.get("version"):
            raise ValueError(f"Pack {name} needs a version and a 64-character SHA-256")
    return packs


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_packs(packs=None, tools_dir=TOOLS_DIR):
    """Compare each downloaded pack archive in .tools with its pinned SHA-256."""
    packs = load_packs() if packs is None else packs
    report = {}
    for name, pack in packs.items():
        archive = Path(tools_dir) / f"{name}.zip"
        binary = Path(tools_dir) / pack["binary"]
        if not archive.is_file():
            status = "installed, archive removed" if binary.is_file() else "missing"
            report[name] = {"status": status, "version": pack["version"], "archive": str(archive)}
            continue
        actual = _sha256(archive)
        report[name] = {"status": "verified" if actual.lower() == pack["sha256"].lower() else "MISMATCH",
                        "version": pack["version"], "archive": str(archive), "sha256": actual}
    return report


def _run_version(command, args, timeout=20):
    key = (tuple(command), tuple(args))
    if key not in _VERSION_CACHE:
        try:
            output = subprocess.run(command + args, capture_output=True, text=True, timeout=timeout,
                                    stdin=subprocess.DEVNULL, errors="replace",
                                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
            text = (output.stdout or output.stderr).strip()
            match = re.search(r"\d+(?:\.\d+)+", text)
            _VERSION_CACHE[key] = match.group(0) if match else None
        except (OSError, subprocess.SubprocessError):
            _VERSION_CACHE[key] = None
    return _VERSION_CACHE[key]


def detect_version(name, command, packs=None):
    """Return (version, how it was found). Never raises; unknown versions are reported as such."""
    info = TOOLS.get(name, {})
    if name == "sqlite":
        import sqlite3
        return sqlite3.sqlite_version, "Python sqlite3 library"
    if info.get("package") and importlib.util.find_spec(name):
        try:
            return importlib.metadata.version(info["package"]), "installed Python package"
        except importlib.metadata.PackageNotFoundError:
            pass
    if not command:
        return None, "not installed"
    if info.get("version_args"):
        version = _run_version(command, info["version_args"])
        if version:
            return version, "reported by the tool"
    # Some tools (ALEAPP) have no version flag: use the pinned pack version when the
    # configured executable is the one setup.ps1 unpacked from that pack.
    packs = packs if packs is not None else _packs_or_empty()
    pack = packs.get(name)
    if pack:
        executable = Path(command[-1] if command[0] == sys.executable else command[0]).resolve()
        if executable == (TOOLS_DIR / pack["binary"]).resolve():
            return pack["version"], "pinned pack installed by setup.ps1"
    return None, "the tool does not report a version"


def _packs_or_empty():
    try:
        return load_packs()
    except (OSError, ValueError):
        return {}


def tool_inventory(config=None):
    """Everything the desktop Tools screen and reports need about each tool."""
    from .config import doctor
    availability = doctor(config or {})
    packs = _packs_or_empty()
    pack_state = verify_packs(packs) if packs else {}
    rows = []
    for name in TOOL_NAMES:
        state = availability[name]
        info = TOOLS[name]
        row = {"name": name, "title": info["title"], "purpose": info["purpose"], "license": info["license"],
               "homepage": info["homepage"], "install": info["install"], "available": state["available"],
               "version": state.get("version"), "version_source": state.get("version_source"),
               "command": state.get("command")}
        if name in packs:
            row["pinned_version"] = packs[name]["version"]
            row["pack"] = pack_state.get(name, {}).get("status")
        rows.append(row)
    return rows


def notices():
    lines = ["Third-party tools used by Mobile DF Automation", "=" * 46, "",
             "These tools keep their own licences. They are downloaded or installed separately",
             "and are not relicensed by this project.", ""]
    for name in TOOL_NAMES:
        info = TOOLS[name]
        lines += [f"{info['title']}", f"  Licence:  {info['license']}", f"  Source:   {info['homepage']}",
                  f"  Install:  {info['install']}", ""]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m mobile_df.registry", description="Forensic tool registry")
    parser.add_argument("--config", type=Path, help="tools.local.json (default: project root)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--json", action="store_true", help="Print the inventory as JSON")
    group.add_argument("--verify", action="store_true", help="Verify downloaded packs against tool-packs.json")
    group.add_argument("--notices", action="store_true", help="Print third-party licence notices")
    args = parser.parse_args(argv)
    if args.notices:
        print(notices())
        return 0
    if args.verify:
        report = verify_packs()
        print(json.dumps(report, indent=2))
        return 1 if any(item["status"] == "MISMATCH" for item in report.values()) else 0
    from .config import load_config
    rows = tool_inventory(load_config(args.config or ROOT / "tools.local.json"))
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    print(f"{'Tool':<28}{'Ready':<7}{'Version':<14}{'Pack':<12}Licence")
    for row in rows:
        print(f"{row['title']:<28}{'yes' if row['available'] else 'no':<7}{row['version'] or '-':<14}"
              f"{row.get('pack') or '-':<12}{row['license']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
