"""Create verified working copies; never pass the original evidence to tools."""
import os
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from .core import sha256


def is_link(path):
    return path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)


def files_under(root):
    if is_link(root):
        raise ValueError(f"Evidence links/reparse points are not supported: {root}")
    if root.is_file():
        return [root]
    files = []
    for current, directories, names in os.walk(root, followlinks=False):
        for name in directories + names:
            path = Path(current) / name
            if is_link(path):
                raise ValueError(f"Evidence links/reparse points are not supported: {path}")
            if path.is_file():
                files.append(path)
    return sorted(files)


def inventory(root):
    base = root if root.is_dir() else root.parent
    return [{"path": path.relative_to(base).as_posix(), "size": path.stat().st_size,
             "mtime_ns": path.stat().st_mtime_ns, "sha256": sha256(path)} for path in files_under(root)]


def archive_target(name, root, seen):
    normalized = name.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if not parts or normalized.startswith("/") or any(
        part in ("..", ".") or ":" in part or part.rstrip(" .") != part or
        part.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(10)], *[f"LPT{i}" for i in range(10)]}
        for part in parts
    ):
        raise ValueError(f"Unsafe archive entry: {name}")
    key = "/".join(parts).casefold()
    if key in seen:
        raise ValueError(f"Duplicate archive entry: {name}")
    seen.add(key)
    destination = root.joinpath(*parts)
    if not destination.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Archive path escapes working directory: {name}")
    return destination


def unpack(source, target, max_bytes, max_files=100000):
    target.mkdir()
    total, count, seen = 0, 0, set()
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                if stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError("Archive symbolic links are not supported")
                total += member.file_size
                count += 1
                if total > max_bytes or count > max_files:
                    raise ValueError("Archive exceeds configured extraction limit")
                path = archive_target(member.filename, target, seen)
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as reader, path.open("xb") as writer:
                    shutil.copyfileobj(reader, writer)
    else:
        with tarfile.open(source) as archive:
            for member in archive:
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError("Archive links and special files are not supported")
                total += member.size
                count += 1
                if total > max_bytes or count > max_files:
                    raise ValueError("Archive exceeds configured extraction limit")
                path = archive_target(member.name, target, seen)
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as reader, path.open("xb") as writer:
                    shutil.copyfileobj(reader, writer)
    return target


def stage(evidence, output, manifest, kind, max_bytes):
    work = output / "working"
    work.mkdir()
    target = work / ("evidence" if evidence.is_dir() else evidence.name)
    if evidence.is_dir():
        target.mkdir()
        for item in manifest:
            destination = target / item["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(evidence / item["path"], destination)
    else:
        shutil.copy2(evidence, target)
    if [{k: item[k] for k in ("path", "size", "sha256")} for item in inventory(target)] != [
        {k: item[k] for k in ("path", "size", "sha256")} for item in manifest
    ]:
        raise ValueError("Evidence changed during copy; working copy verification failed")
    if kind == "archive":
        return unpack(target, work / "extracted", max_bytes)
    return target


def detect_kind(path, requested="auto"):
    if requested != "auto":
        return requested
    if path.is_dir():
        return "directory"
    if path.suffix.lower() == ".ab":
        return "backup"
    if zipfile.is_zipfile(path) or tarfile.is_tarfile(path):
        return "archive"
    return "image"
