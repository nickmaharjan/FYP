"""Create verified working copies; never pass the original evidence to tools."""
import os
import re
import string
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


def inventory(root, files=None):
    """Hash every evidence file. ``files`` lists all segments of a split image (default: just ``root``)."""
    base = root if root.is_dir() else root.parent
    paths = files_under(root) if files is None else [Path(f) for f in files]
    return [{"path": path.relative_to(base).as_posix(), "size": path.stat().st_size,
             "mtime_ns": path.stat().st_mtime_ns, "sha256": sha256(path)} for path in paths]


def _ewf_suffixes():
    """EnCase segment names in order: .E01-.E99, then .EAA-.EZZ."""
    yield from (f"E{n:02d}" for n in range(1, 100))
    yield from (f"E{a}{b}" for a in string.ascii_uppercase for b in string.ascii_uppercase)


def ewf_end_marker(path):
    """The type of an EnCase segment's last section: 'done' for the final segment, 'next' if more follow."""
    try:
        with Path(path).open("rb") as stream:
            stream.seek(-76, os.SEEK_END)
            kind = stream.read(16).rstrip(b"\x00")
    except OSError:
        return None
    return kind.decode("ascii", "replace") if kind in (b"done", b"next") else None


def image_segments(path):
    """Return (segments, problem) for a disk image that may be split into several files.

    Recognises EnCase sets (.E01, .E02, ...) and raw splits (.001, .002, ...) starting from the
    first segment. ``problem`` explains a set that is known to be incomplete, otherwise None.
    """
    path = Path(path)
    suffix = path.suffix
    if re.fullmatch(r"\.[Ee]01", suffix):
        upper = suffix[1] == "E"
        names = (s if upper else s.lower() for s in _ewf_suffixes())
    elif suffix == ".001":
        names = (f"{n:03d}" for n in range(1, 1000))
    elif re.fullmatch(r"\.([Ee]\d\d|[Ee][A-Za-z]{2}|\d{3})", suffix):
        first = "E01" if suffix[1] in "Ee" else "001"
        return [path], (f"{path.name} is not the first segment of a split image; choose "
                        f"{path.with_suffix('.' + (first if suffix[1] != 'e' else first.lower())).name} instead")
    else:
        return [path], None
    segments = []
    for name in names:
        candidate = path.with_suffix("." + name)
        if not candidate.is_file():
            missing = candidate.name
            break
        segments.append(candidate)
    else:
        missing = None
    problem = None
    if suffix[1] in "Ee" and missing and ewf_end_marker(segments[-1]) == "next":
        problem = (f"Image segment set is incomplete: {segments[-1].name} says more data follows but {missing} "
                   f"is missing. Put every segment in the same folder and analyse again.")
    return segments, problem


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
        copied = None
    else:
        # A split image is copied segment by segment, keeping the names tools use to find the rest.
        copied = [work / item["path"] for item in manifest]
        for item, destination in zip(manifest, copied):
            shutil.copy2(evidence.parent / item["path"], destination)
    if [{k: item[k] for k in ("path", "size", "sha256")} for item in inventory(target, copied)] != [
        {k: item[k] for k in ("path", "size", "sha256")} for item in manifest
    ]:
        raise ValueError("Evidence changed during copy; working copy verification failed")
    if kind == "archive":
        return unpack(target, work / "extracted", max_bytes)
    return target


ARCHIVE_SUFFIXES = (".zip", ".tar", ".tgz", ".tar.gz", ".tbz2", ".tar.bz2", ".txz", ".tar.xz")


def detect_kind(path, requested="auto"):
    if requested != "auto":
        return requested
    if path.is_dir():
        return "directory"
    if path.suffix.lower() == ".ab":
        return "backup"
    if zipfile.is_zipfile(path) or tarfile.is_tarfile(path):
        return "archive"
    name = path.name.lower()
    if name.endswith(ARCHIVE_SUFFIXES):
        # Without this, a damaged or partly copied archive is treated as a disk image,
        # no extraction tool applies, and the case reports "completed" with nothing analysed.
        raise ValueError(f"{path.name} is named like an archive but is not a readable ZIP or TAR file; "
                         "it may be damaged, incomplete or in an unsupported format. "
                         "If it is really a disk image, analyse it from the command line with --kind image.")
    return "image"
