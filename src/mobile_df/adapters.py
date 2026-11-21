"""Tool adapters: commands, applicability, and provenance-preserving parsers."""
import csv
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .config import command_for, plaso_docker_image
from .core import artifact, relative_source, timestamp_from
from .runner import execute


@dataclass
class Context:
    evidence: Path
    output: Path
    kind: str
    config: dict
    timeout: int = 300
    max_rows: int = 1000
    max_findings: int = 50000
    yara_rules: Path | None = None
    iocs: Path | None = None
    mvt_mode: str = "auto"
    image_offset: int = 0
    cancel: object = None
    steps: list = field(default_factory=list)
    segments: list = field(default_factory=list)     # every file of a split disk image, first segment first
    segment_problem: str | None = None

    def run(self, name, command, env=None):
        env = dict(env or {})
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        result = execute(name, command, self.output, self.timeout, self.cancel, env)
        self.steps.append(result)
        return result

    def directory(self, name):
        path = self.output / "tools" / name
        path.mkdir(parents=True, exist_ok=True)
        return path


class Adapter:
    name = ""

    def applicable(self, ctx):
        return None

    def run(self, ctx):
        raise NotImplementedError


def json_lines(path, limit):
    values = []
    with path.open(encoding="utf-8-sig", errors="replace") as stream:
        for line in stream:
            if line.strip():
                values.append(json.loads(line))
                if len(values) >= limit:
                    break
    return values


class SQLiteAdapter(Adapter):
    name = "sqlite"

    def applicable(self, ctx):
        return None if ctx.evidence.is_dir() else "Requires extracted files; image recovery has not produced a directory"

    def run(self, ctx):
        step = ctx.run(self.name, [sys.executable, "-m", "mobile_df.worker", "sqlite", str(ctx.evidence), "--max-rows", str(ctx.max_rows)])
        summary = self.summary(ctx.output / step["stderr_log"])
        if (step["status"] == "failed" and step["exit_code"] == 1 and summary
                and summary["unreadable_databases"] < summary["databases"]):
            # The worker exits 1 when some databases or tables could not be read but the rest were
            # exported; that is a partial result, not a tool failure.
            parts = []
            if summary["unreadable_databases"]:
                parts.append(f"{summary['unreadable_databases']} of {summary['databases']} databases")
            if summary["unreadable_tables"]:
                count = summary["unreadable_tables"]
                parts.append(f"{count} table{'s' if count != 1 else ''}")
            names = ", ".join(summary.get("examples", []))
            step["status"] = "partial"
            step["reason"] = (f"SQLite could not read {' and '.join(parts)} (corrupt, encrypted or unsupported)"
                              f"{': ' + names if names else ''}; see analysis_error findings")
        return json_lines(ctx.output / step["stdout_log"], ctx.max_findings)

    @staticmethod
    def summary(path):
        """The worker's last stderr line: counts of databases and tables it could not read."""
        try:
            lines = [line for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
            value = json.loads(lines[-1]) if lines else None
        except (OSError, ValueError):
            return None
        return value if isinstance(value, dict) and "unreadable_databases" in value else None


class YaraAdapter(Adapter):
    name = "yara"

    def applicable(self, ctx):
        return None if ctx.yara_rules else "No YARA rules supplied"

    def run(self, ctx):
        step = ctx.run(self.name, [sys.executable, "-m", "mobile_df.worker", "yara", str(ctx.evidence), "--rules", str(ctx.yara_rules)])
        return json_lines(ctx.output / step["stdout_log"], ctx.max_findings)


class ExifToolAdapter(Adapter):
    name = "exiftool"

    def applicable(self, ctx):
        return None if ctx.evidence.is_dir() else "Metadata extraction requires an extraction directory"

    def run(self, ctx):
        command = command_for(self.name, ctx.config) + ["-json", "-r", "-G1", "-n",
                   "-ext", "jpg", "-ext", "jpeg", "-ext", "png", "-ext", "heic",
                   "-ext", "mp4", "-ext", "pdf", str(ctx.evidence)]
        step = ctx.run(self.name, command)
        path = ctx.output / step["stdout_log"]
        if not path.stat().st_size:
            return []
        values = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
        if not isinstance(values, list):
            raise ValueError("ExifTool output must be a JSON array")
        unreadable = [row for row in values if isinstance(row, dict) and ("ExifTool:Error" in row or "Error" in row)]
        if step["status"] == "failed" and step["exit_code"] == 1 and values:
            # ExifTool exits 1 when any single file cannot be read (for example NTFS-encrypted files)
            # even though every other file was processed; that is a partial result, not a tool failure.
            step["status"] = "partial"
            names = ", ".join(relative_source(row.get("SourceFile", ""), ctx.evidence) for row in unreadable[:3])
            step["reason"] = (f"ExifTool could not read {len(unreadable)} of {len(values)} files "
                              f"(encrypted, corrupt or unsupported){': ' + names if names else ''}")
        return [artifact(self.name, "metadata", relative_source(row.pop("SourceFile", ""), ctx.evidence), row,
                         severity="warning" if row in unreadable else "info",
                         provenance={"output": step["stdout_log"], "record": i + 1})
                for i, row in enumerate(values[:ctx.max_findings])]


class AleappAdapter(Adapter):
    name = "aleapp"

    def applicable(self, ctx):
        return None if ctx.evidence.is_dir() else "ALEAPP adapter uses an extracted filesystem directory"

    def run(self, ctx):
        directory = ctx.directory(self.name)
        command = command_for(self.name, ctx.config) + ["-t", "fs", "-i", str(ctx.evidence), "-o", str(directory)]
        ctx.run(self.name, command)
        results = []
        for path in sorted(directory.rglob("*.tsv")):
            with path.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
                reader = csv.DictReader(stream, delimiter="\t")
                for index, row in enumerate(reader):
                    stamp, basis = timestamp_from(row)
                    source = next((v for k, v in row.items() if k and k.lower() in ("source", "source file", "source_file", "source path")), "")
                    results.append(artifact(self.name, "android_artifact",
                                           relative_source(source, ctx.evidence) if source else f"tool-output:{path.relative_to(ctx.output).as_posix()}",
                                           dict(row), stamp, basis,
                                           provenance={"output": path.relative_to(ctx.output).as_posix(), "row": index + 2}))
                    if len(results) >= ctx.max_findings:
                        return results
        return results


class MVTAdapter(Adapter):
    name = "mvt"

    def mode(self, ctx):
        if ctx.mvt_mode != "auto":
            return ctx.mvt_mode
        if ctx.evidence.suffix.lower() == ".ab" or (ctx.evidence / "apps").is_dir():
            return "backup"
        if ctx.evidence.is_dir() and list(ctx.evidence.glob("bugreport*.txt")):
            return "bugreport"
        return None

    def applicable(self, ctx):
        if not self.mode(ctx):
            return "Requires Android backup/apps directory, bugreport, or explicit --mvt-mode androidqf"
        return None

    def run(self, ctx):
        directory = ctx.directory(self.name)
        command = command_for(self.name, ctx.config) + ["check-" + self.mode(ctx), "--output", str(directory)]
        if ctx.iocs:
            command += ["--iocs", str(ctx.iocs)]
        command += [str(ctx.evidence)]
        private = str(ctx.directory("mvt-settings"))
        env = {"MVT_NETWORK_ACCESS_ALLOWED": "false", "MVT_STIX2": "",
               "MOBILE_DF_MVT_SETTINGS": private, "XDG_CONFIG_HOME": private, "XDG_DATA_HOME": private}
        ctx.run(self.name, command, env)
        results = []
        for path in sorted(directory.rglob("*.json")):
            # info.json is run metadata, not recovered device activity. alerts.json
            # duplicates the module *_detected files in recent MVT versions.
            if path.name == "info.json" or (path.stem.endswith("_detected") and (directory / "alerts.json").exists()):
                continue
            values = json.loads(path.read_text(encoding="utf-8-sig"))
            values = values if isinstance(values, list) else [values]
            for index, row in enumerate(values):
                if not isinstance(row, dict):
                    row = {"value": row}
                stamp, basis = timestamp_from(row)
                if not stamp and isinstance(row.get("event"), dict):
                    stamp, basis = timestamp_from(row["event"])
                if not stamp and path.stem == "urls" and row.get("timestamp"):
                    stamp, basis = timestamp_from({"timestamp": str(row["timestamp"]) + "+00:00"})
                    basis = "MVT URL export timestamp is UTC; raw value retained" if stamp else None
                detected = "detected" in path.stem or path.stem == "alerts"
                results.append(artifact(self.name, "indicator" if detected else "mobile_artifact",
                                       f"tool-output:{path.relative_to(ctx.output).as_posix()}", row, stamp, basis,
                                       "warning" if detected else "info",
                                       {"output": path.relative_to(ctx.output).as_posix(), "record": index + 1}))
                if len(results) >= ctx.max_findings:
                    return results
        return results


# fls "body file" columns: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime (UTC epoch seconds).
BODY_TIMES = (("modified", 8, "m"), ("accessed", 7, "a"), ("changed", 9, "c"), ("created", 10, "b"))
FILE_NAME_SUFFIX = " ($FILE_NAME)"
DELETED_SUFFIXES = (" (deleted-realloc)", " (deleted)")


def _epoch(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    try:
        return datetime.fromtimestamp(number, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def parse_bodyfile(lines, mount="/"):
    """Group fls -m output into one entry per file, keeping NTFS $FILE_NAME times beside the main times."""
    entries, order = {}, []
    for number, line in enumerate(lines, 1):
        fields = line.rstrip("\r\n").split("|")
        if len(fields) < 11:
            continue
        name = "|".join(fields[1:-9])          # file names may themselves contain "|"
        inode, mode, size = fields[-9], fields[-8], fields[-5]
        file_name_attribute = name.endswith(FILE_NAME_SUFFIX)
        if file_name_attribute:
            name = name[:-len(FILE_NAME_SUFFIX)]
        deleted = False
        for suffix in DELETED_SUFFIXES:
            if name.endswith(suffix):
                name, deleted = name[:-len(suffix)], True
                break
        path = name[len(mount):] if mount and name.startswith(mount) else name
        times = {label: _epoch(fields[index - 11]) for label, index, _ in BODY_TIMES}
        key = (path, inode.split("-")[0], deleted)
        entry = entries.get(key)
        if entry is None:
            entry = entries[key] = {"path": path, "metadata_address": inode, "mode": mode, "deleted": deleted,
                                    "times": {}, "line": number}
            order.append(key)
        if file_name_attribute:
            entry["file_name_times"] = times
        else:
            entry.update(metadata_address=inode, mode=mode, times=times, line=number)
            entry["size"] = int(size) if size.isdigit() else size
    return [entries[key] for key in order]


def timestamp_anomaly(entry):
    """NTFS lead: $STANDARD_INFORMATION created earlier than $FILE_NAME created suggests the time was set back."""
    standard = entry["times"].get("created")
    file_name = (entry.get("file_name_times") or {}).get("created")
    if standard and file_name and standard < file_name:
        return {"standard_information_created": standard, "file_name_created": file_name}
    return None


class SleuthKitAdapter(Adapter):
    name = "sleuthkit"

    def applicable(self, ctx):
        return None if ctx.kind == "image" and ctx.evidence.is_file() else "Filesystem tools require a raw filesystem/disk image"

    def image_arguments(self, ctx):
        # libewf finds .E02 onwards from the .E01 name; raw splits must be listed in order.
        segments = ctx.segments or [ctx.evidence]
        return [str(path) for path in segments] if segments[0].suffix == ".001" else [str(ctx.evidence)]

    def run(self, ctx):
        images = self.image_arguments(ctx)
        step = ctx.run(self.name, command_for(self.name, ctx.config) + ["-r", "-m", "/", "-z", "UTC", "-o", str(ctx.image_offset)] + images)
        if step["status"] != "success" and ctx.segment_problem:
            step["reason"] = ctx.segment_problem
        with (ctx.output / step["stdout_log"]).open(encoding="utf-8", errors="replace") as stream:
            entries = parse_bodyfile(stream)
        results = []
        provenance = lambda entry: {"output": step["stdout_log"], "line": entry["line"]}
        for entry in entries:
            detail = {key: entry[key] for key in ("metadata_address", "mode", "size", "deleted", "times", "file_name_times") if key in entry}
            results.append(artifact(self.name, "filesystem_entry", entry["path"], detail,
                                   severity="warning" if entry["deleted"] else "info", provenance=provenance(entry)))
            # One timeline event per distinct time, labelled with mactime-style MACB flags.
            labels = {}
            for label, _, flag in BODY_TIMES:
                stamp = entry["times"].get(label)
                if stamp:
                    labels.setdefault(stamp, []).append((label, flag))
            for stamp, hits in sorted(labels.items()):
                flags = "".join(flag if any(f == flag for _, f in hits) else "." for flag in "macb")
                results.append(artifact(self.name, "file_time", entry["path"],
                                       {"macb": flags, "times": [label for label, _ in hits], "deleted": entry["deleted"],
                                        "metadata_address": entry["metadata_address"]},
                                       stamp, f"fls body file {flags} time (epoch seconds, -z UTC); filesystems that store local time "
                                       "without a zone (FAT/exFAT) are read as UTC",
                                       provenance=provenance(entry)))
            anomaly = timestamp_anomaly(entry)
            if anomaly:
                results.append(artifact(self.name, "timestamp_anomaly", entry["path"],
                                       dict(anomaly, note="$STANDARD_INFORMATION creation predates $FILE_NAME creation; "
                                                          "a possible sign of timestamp manipulation that needs review"),
                                       severity="warning", provenance=provenance(entry)))
            if len(results) >= ctx.max_findings:
                results = results[:ctx.max_findings]
                break
        recover = command_for("tsk_recover", ctx.config)
        if recover and step["status"] == "success":
            directory = ctx.directory("recovered")
            recovery = ctx.run("sleuthkit-recover", recover + ["-a", "-o", str(ctx.image_offset)] + images + [str(directory)])
            if recovery["status"] == "success":
                ctx.evidence = directory
        return results


CONTAINER_EVIDENCE, CONTAINER_OUTPUT = "/evidence", "/output"


def container_relative(value, evidence_name):
    """Map a path seen inside the Plaso container back to a path relative to the evidence."""
    text = str(value or "")
    root = f"{CONTAINER_EVIDENCE}/{evidence_name}"
    if text == root:
        return evidence_name
    if text.startswith(root + "/"):
        return text[len(root) + 1:]
    # Plaso shows paths inside an image or archive as "<source>:/inner/path" or just "/inner/path".
    return text.split(":", 1)[1].lstrip("/") if text.startswith(root + ":") else text.lstrip("/")


class PlasoAdapter(Adapter):
    name = "plaso"

    def _docker(self, ctx, image, mounts, arguments):
        command = command_for("docker", ctx.config) + ["run", "--rm", "--network", "none"]
        for host, container, mode in mounts:
            command += ["-v", f"{host}:{container}:{mode}"]
        return command + [image] + arguments

    def run(self, ctx):
        directory = ctx.directory(self.name)
        storage, events = directory / "timeline.plaso", directory / "events.jsonl"
        image = None if command_for(self.name, ctx.config) and command_for("psort", ctx.config) else plaso_docker_image(ctx.config)
        if image:
            # Evidence is mounted read-only and the container has no network access.
            evidence_mount = (str(ctx.evidence.parent), CONTAINER_EVIDENCE, "ro")
            output_mount = (str(directory), CONTAINER_OUTPUT, "rw")
            source = f"{CONTAINER_EVIDENCE}/{ctx.evidence.name}"
            extract = self._docker(ctx, image, [evidence_mount, output_mount],
                                   ["log2timeline.py", "--status_view", "none", "--unattended",
                                    "--storage-file", f"{CONTAINER_OUTPUT}/{storage.name}", source])
            export_command = self._docker(ctx, image, [output_mount],
                                          ["psort.py", "--status_view", "none", "-o", "json_line", "-w",
                                           f"{CONTAINER_OUTPUT}/{events.name}", f"{CONTAINER_OUTPUT}/{storage.name}"])
            to_path = lambda value: container_relative(value, ctx.evidence.name)
        else:
            extract = command_for(self.name, ctx.config) + ["--storage-file", str(storage), str(ctx.evidence)]
            export_command = command_for("psort", ctx.config) + ["-o", "json_line", "-w", str(events), str(storage)]
            to_path = lambda value: relative_source(value, ctx.evidence)
        step = ctx.run(self.name, extract)
        if step["status"] != "success":
            return []
        export = ctx.run("plaso-export", export_command)
        if export["status"] != "success" or not events.is_file():
            return []
        results = []
        for index, row in enumerate(json_lines(events, ctx.max_findings)):
            stamp, basis = timestamp_from(row)
            results.append(artifact(self.name, "timeline_event", to_path(row.get("filename", row.get("display_name", ""))),
                                   row, stamp, basis, provenance={"output": events.relative_to(ctx.output).as_posix(), "line": index + 1}))
        return results


# Image recovery runs first so all subsequent file-based adapters can use its output.
ADAPTERS = [SleuthKitAdapter(), SQLiteAdapter(), YaraAdapter(), ExifToolAdapter(), AleappAdapter(), MVTAdapter(), PlasoAdapter()]
