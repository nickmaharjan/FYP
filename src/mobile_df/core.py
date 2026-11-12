"""Shared artifact schema, timestamp handling and bounded output parsing."""
import hashlib
import json
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlsplit

TOOL_NAMES = ("sqlite", "yara", "exiftool", "aleapp", "mvt", "sleuthkit", "plaso")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def normalize_time(value, field=""):
    """Return UTC only for explicit zones or recognized epoch encodings."""
    if value in (None, "", 0, "0"):
        return None
    try:
        number = float(value)
        if field.lower() in ("visit_time", "last_visit_time") and number > 1e16:
            dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=number)
        else:
            seconds = number / (1e6 if abs(number) > 1e14 else 1e3 if abs(number) > 1e11 else 1)
            dt = datetime.fromtimestamp(seconds, timezone.utc)
        return dt.isoformat() if 1990 <= dt.year <= 2100 else None
    except (ValueError, TypeError, OverflowError, OSError):
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).isoformat() if dt.tzinfo else None
        except ValueError:
            return None


def timestamp_from(values):
    for key, value in values.items():
        if key.lower().replace(" ", "_") in {
            "date", "date_sent", "timestamp", "datetime", "time", "visit_time",
            "last_visit_time", "timestamp_utc", "isodate", "creation_time", "created_at",
        }:
            stamp = normalize_time(value, key)
            if stamp:
                return stamp, f"{key}: recognized epoch or explicit timezone; raw value retained"
    return None, None


def entities(detail):
    text = json.dumps(detail, ensure_ascii=False)
    found = set()
    for url in re.findall(r'https?://[^\s<>"\\]+', text):
        url = url.rstrip(".,);]")
        found.add(("url", url))
        try:
            if urlsplit(url).hostname:
                found.add(("domain", urlsplit(url).hostname.lower()))
        except ValueError:
            pass
    for value in re.findall(r"\b[A-Fa-f0-9]{64}\b", text):
        found.add(("sha256", value.lower()))
    return [{"type": key, "value": value} for key, value in sorted(found)]


def artifact(source, kind, path, detail, timestamp=None, basis=None, severity="info", provenance=None):
    result = {"source": source, "kind": kind, "path": str(path), "detail": detail,
              "timestamp": timestamp, "timestamp_basis": basis, "severity": severity,
              "provenance": provenance or {}, "entities": entities(detail)}
    result["id"] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()[:24]
    return result


def relative_source(path, evidence):
    value = str(path).removeprefix("\\\\?\\")
    try:
        return Path(value).resolve().relative_to(evidence.resolve()).as_posix()
    except (ValueError, OSError):
        return value


def correlate(findings):
    groups = {}
    for item in findings:
        if item["path"] and not item["path"].startswith("tool-output:"):
            groups.setdefault(("path", item["path"]), []).append(item)
        for entity in item["entities"]:
            groups.setdefault((entity["type"], entity["value"]), []).append(item)
    correlations = []
    for (kind, value), members in sorted(groups.items()):
        unique = {item["id"]: item for item in members}
        sources = sorted({item["source"] for item in unique.values()})
        if len(sources) < 2:
            continue
        correlations.append({"type": kind, "value": value, "sources": sources,
                             "finding_ids": list(unique),
                             "interpretation": "Exact shared value; association does not establish causation or compromise."})
    return correlations
