"""Tool adapters: commands, applicability, and provenance-preserving parsers."""
import csv
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .config import command_for
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
        return json_lines(ctx.output / step["stdout_log"], ctx.max_findings)


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
        return [artifact(self.name, "metadata", relative_source(row.pop("SourceFile", ""), ctx.evidence), row,
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


class SleuthKitAdapter(Adapter):
    name = "sleuthkit"

    def applicable(self, ctx):
        return None if ctx.kind == "image" and ctx.evidence.is_file() else "Filesystem tools require a raw filesystem/disk image"

    def run(self, ctx):
        step = ctx.run(self.name, command_for(self.name, ctx.config) + ["-r", "-p", "-o", str(ctx.image_offset), str(ctx.evidence)])
        results = []
        with (ctx.output / step["stdout_log"]).open(encoding="utf-8", errors="replace") as stream:
            for index, line in enumerate(stream):
                if line.strip():
                    entry, separator, path = line.strip().partition(":\t")
                    results.append(artifact(self.name, "filesystem_entry", path if separator else ctx.evidence.name,
                                           {"entry": line.strip(), "metadata_address": entry},
                                           provenance={"output": step["stdout_log"], "line": index + 1}))
                if len(results) >= ctx.max_findings:
                    break
        recover = command_for("tsk_recover", ctx.config)
        if recover and step["status"] == "success":
            directory = ctx.directory("recovered")
            recovery = ctx.run("sleuthkit-recover", recover + ["-a", "-o", str(ctx.image_offset), str(ctx.evidence), str(directory)])
            if recovery["status"] == "success":
                ctx.evidence = directory
        return results


class PlasoAdapter(Adapter):
    name = "plaso"

    def run(self, ctx):
        directory = ctx.directory(self.name)
        storage, events = directory / "timeline.plaso", directory / "events.jsonl"
        step = ctx.run(self.name, command_for(self.name, ctx.config) + ["--storage-file", str(storage), str(ctx.evidence)])
        if step["status"] != "success":
            return []
        export = ctx.run("plaso-export", command_for("psort", ctx.config) + ["-o", "json_line", "-w", str(events), str(storage)])
        if export["status"] != "success":
            return []
        results = []
        for index, row in enumerate(json_lines(events, ctx.max_findings)):
            stamp, basis = timestamp_from(row)
            results.append(artifact(self.name, "timeline_event",
                                   relative_source(row.get("filename", row.get("display_name", "")), ctx.evidence),
                                   row, stamp, basis, provenance={"output": events.relative_to(ctx.output).as_posix(), "line": index + 1}))
        return results


# Image recovery runs first so all subsequent file-based adapters can use its output.
ADAPTERS = [SleuthKitAdapter(), SQLiteAdapter(), YaraAdapter(), ExifToolAdapter(), AleappAdapter(), MVTAdapter(), PlasoAdapter()]
