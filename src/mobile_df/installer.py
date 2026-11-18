"""Install, update and repair the pinned portable tool packs from inside the application.

Packs and their SHA-256 come from ``tool-packs.json`` (the same list scripts/setup.ps1 uses).
A pack is taken from an offline kit folder when one is given, otherwise downloaded over HTTPS.
Nothing is unpacked until the archive matches its pinned hash. The new copy is unpacked beside
the old one and only swapped in once its executable is present, so a failed or cancelled
update leaves the working installation untouched. ``tools.local.json`` is updated to point at
the installed executables, keeping any other commands the user configured.

    python -m mobile_df.installer status
    python -m mobile_df.installer install all
    python -m mobile_df.installer install exiftool --pack-dir E:\\mobile-df-packs --offline
"""
import argparse
import hashlib
import json
import shutil
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .core import utc_now, write_json
from .registry import ROOT, TOOLS_DIR, load_packs

STATE_FILE = "installed.json"
EXTRA_COMMANDS = {"sleuthkit": {"tsk_recover": "tsk_recover.exe"}}   # other executables shipped in a pack
MAX_UNPACKED_BYTES = 4 * 1024 ** 3
CHUNK = 256 * 1024


class InstallCancelled(Exception):
    pass


def _state(tools_dir):
    try:
        value = json.loads((Path(tools_dir) / STATE_FILE).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def pack_status(packs=None, tools_dir=TOOLS_DIR):
    """For each pack: not installed, up to date, update available or damaged (executable missing)."""
    packs = load_packs() if packs is None else packs
    state = _state(tools_dir)
    report = {}
    for name, pack in packs.items():
        installed = state.get(name, {}).get("version")
        binary = Path(tools_dir) / pack["binary"]
        if not binary.is_file():
            status = "damaged" if installed else "not installed"
        elif installed is None:
            status = "installed by setup script"
        elif installed != pack["version"]:
            status = "update available"
        else:
            status = "up to date"
        report[name] = {"status": status, "installed_version": installed, "pinned_version": pack["version"],
                        "action": {"not installed": "Install", "damaged": "Repair",
                                   "update available": "Update"}.get(status)}
    return report


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def _matches(path, pack):
    return path.is_file() and _sha256(path).lower() == pack["sha256"].lower()


def _download(url, destination, progress, cancel, opener):
    scheme = urlsplit(url).scheme.lower()
    if scheme not in ("https", "file"):
        raise ValueError(f"Refusing to download over {scheme or 'an unknown scheme'}; packs must use HTTPS")
    temporary = destination.with_name(destination.name + ".partial")
    try:
        with opener(Request(url, headers={"User-Agent": "mobile-df-installer"}), timeout=60) as response, \
                temporary.open("wb") as target:
            total = int(response.headers.get("Content-Length") or 0) if hasattr(response, "headers") else 0
            done = 0
            while True:
                if cancel and cancel.is_set():
                    raise InstallCancelled("Download cancelled")
                block = response.read(CHUNK)
                if not block:
                    break
                target.write(block)
                done += len(block)
                if progress:
                    progress("download", done, total)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_member(name):
    parts = PurePosixPath(name.replace("\\", "/")).parts
    if not parts or name.startswith(("/", "\\")) or any(part in ("..", "") or ":" in part for part in parts):
        raise ValueError(f"Unsafe path in tool pack: {name}")
    return parts


def _unpack(archive, target, progress, cancel):
    with zipfile.ZipFile(archive) as bundle:
        members = [m for m in bundle.infolist() if not m.is_dir()]
        if sum(m.file_size for m in members) > MAX_UNPACKED_BYTES:
            raise ValueError("Tool pack is larger than the unpack limit")
        for index, member in enumerate(members, 1):
            if cancel and cancel.is_set():
                raise InstallCancelled("Install cancelled")
            if stat.S_ISLNK(member.external_attr >> 16):
                raise ValueError("Tool packs with symbolic links are not supported")
            path = target.joinpath(*_safe_member(member.filename))
            if not path.resolve().is_relative_to(target.resolve()):
                raise ValueError(f"Unsafe path in tool pack: {member.filename}")
            path.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as reader, path.open("wb") as writer:
                shutil.copyfileobj(reader, writer)
            if progress:
                progress("unpack", index, len(members))


def _remove_tree(path):
    def clear_readonly(function, target, _info):
        Path(target).chmod(stat.S_IWRITE)
        function(target)
    if path.exists():
        shutil.rmtree(path, onerror=clear_readonly)


def update_config(config_path, name, pack, tools_dir):
    """Point tools.local.json at the installed executables, keeping every other entry."""
    config_path = Path(config_path)
    try:
        config = json.loads(config_path.read_text(encoding="utf-8-sig")) if config_path.exists() else {}
    except ValueError:
        raise ValueError(f"{config_path.name} is not valid JSON; fix or delete it, then install again")
    commands = config.setdefault("commands", {})
    binary = (Path(tools_dir) / pack["binary"]).resolve()
    commands[name] = [str(binary)]
    for key, filename in EXTRA_COMMANDS.get(name, {}).items():
        extra = binary.parent / filename
        if extra.is_file():
            commands[key] = [str(extra)]
    write_json(config_path, config)


def install_pack(name, packs=None, tools_dir=TOOLS_DIR, config_path=None, pack_dir=None, offline=False,
                 progress=None, cancel=None, opener=urlopen):
    """Install or update one pinned pack. Returns a summary; raises on any failure with nothing swapped in."""
    packs = load_packs() if packs is None else packs
    if name not in packs:
        raise ValueError(f"No pinned pack for {name}; available: {', '.join(sorted(packs))}")
    pack = packs[name]
    tools_dir = Path(tools_dir)
    tools_dir.mkdir(parents=True, exist_ok=True)
    archive = tools_dir / f"{name}.zip"
    source = "existing verified archive"
    if not _matches(archive, pack):
        archive.unlink(missing_ok=True)
        kit = Path(pack_dir) / f"{name}.zip" if pack_dir else None
        if kit and kit.is_file():
            shutil.copyfile(kit, archive)
            source = f"offline kit {Path(pack_dir)}"
        elif offline:
            raise ValueError(f"Offline install needs {name}.zip in the pack folder")
        else:
            _download(pack["url"], archive, progress, cancel, opener)
            source = pack["url"]
        if progress:
            progress("verify", 0, 0)
        if not _matches(archive, pack):
            archive.unlink(missing_ok=True)
            raise ValueError(f"{name} pack does not match its pinned SHA-256; it was deleted and nothing was installed")
    staging = tools_dir / f"{name}.new"
    _remove_tree(staging)
    try:
        _unpack(archive, staging, progress, cancel)
        if not (staging / Path(pack["binary"]).relative_to(name)).is_file():
            raise ValueError(f"{name} pack does not contain {pack['binary']}")
        current, previous = tools_dir / name, tools_dir / f"{name}.old"
        _remove_tree(previous)
        if current.exists():
            current.rename(previous)
        staging.rename(current)
        _remove_tree(previous)
    except BaseException:
        _remove_tree(staging)
        raise
    state = _state(tools_dir)
    state[name] = {"version": pack["version"], "sha256": pack["sha256"].lower(), "installed_utc": utc_now(),
                   "source": source}
    write_json(tools_dir / STATE_FILE, state)
    update_config(config_path or ROOT / "tools.local.json", name, pack, tools_dir)
    return {"tool": name, "version": pack["version"], "source": source,
            "executable": str((tools_dir / pack["binary"]).resolve())}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m mobile_df.installer", description="Install pinned tool packs")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Show installed and pinned versions")
    install = commands.add_parser("install", help="Install, update or repair packs")
    install.add_argument("tools", nargs="+", help="Pack names, or 'all'")
    install.add_argument("--pack-dir", type=Path, help="Offline kit folder with <name>.zip files")
    install.add_argument("--offline", action="store_true", help="Never use the network")
    args = parser.parse_args(argv)
    try:
        packs = load_packs()
        if args.command == "status":
            print(json.dumps(pack_status(packs), indent=2))
            return 0
        names = sorted(packs) if args.tools == ["all"] else args.tools
        for name in names:
            def report(stage, done, total, name=name):
                if stage == "download" and total:
                    print(f"\r{name}: downloading {done * 100 // total}%", end="", file=sys.stderr, flush=True)
            summary = install_pack(name, packs, pack_dir=args.pack_dir, offline=args.offline, progress=report)
            print(f"\n{name} {summary['version']} installed from {summary['source']}", file=sys.stderr)
        return 0
    except (OSError, ValueError, zipfile.BadZipFile, InstallCancelled) as exc:
        parser.exit(2, f"\nerror: {exc}\n")


if __name__ == "__main__":
    sys.exit(main())
