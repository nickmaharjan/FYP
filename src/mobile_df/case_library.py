"""Read-only case library used by the desktop workbench.

Loads saved case results, summarizes them for the case list, and filters
findings and timeline events for in-app review. Nothing here modifies a case.
"""
import csv
import json
import os
import shutil
import stat
import sys
from pathlib import Path

ARCHIVE_FOLDER = "_archive"
SEVERITY_ORDER = {"critical": 0, "high": 1, "warning": 2, "medium": 2, "low": 3, "info": 4}
ACTIVE_STATUSES = {"running", "pending"}


def _load(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def case_summary(folder):
    """Return a list-row summary for a case folder, or None if it is not a case."""
    folder = Path(folder)
    result = _load(folder / "results.json")
    if result is None:
        status = _load(folder / "status.json")
        if status is None:
            return None
        # Analysis started but results were never written: interrupted or still running.
        rerun = status.get("rerun") if isinstance(status.get("rerun"), dict) else {}
        return {"folder": str(folder), "case_id": status.get("case_id", folder.name),
                "status": "incomplete", "started_utc": status.get("started_utc") or "", "completed_utc": "",
                "findings": 0, "timeline_events": 0, "correlations": 0,
                "integrity": "unknown", "evidence": rerun.get("evidence", ""), "report": None}
    metrics = result.get("metrics") or {}
    report = folder / "report.html"
    return {"folder": str(folder), "case_id": result.get("case_id", folder.name),
            "status": result.get("status", "unknown"),
            "started_utc": result.get("started_utc") or "",
            "completed_utc": result.get("completed_utc") or "",
            "findings": metrics.get("findings", len(result.get("findings") or [])),
            "timeline_events": metrics.get("timeline_events", len(result.get("timeline") or [])),
            "correlations": metrics.get("correlations", len(result.get("correlations") or [])),
            "integrity": (result.get("integrity") or {}).get("status", "unknown"),
            "evidence": result.get("evidence", ""),
            "report": str(report) if report.is_file() else None}


RERUN_KEYS = ("evidence", "case_id", "kind", "mvt_mode", "tools", "timeout", "max_rows", "max_findings",
              "max_extract_gb", "image_offset", "yara_rules", "iocs")


def rerun_options(folder):
    """Options to analyze an interrupted case again, as recorded when it started.

    Raises ValueError when the case finished, was recorded before re-run support,
    or its evidence / rules / indicators are no longer where they were.
    """
    folder = Path(folder)
    if (folder / "results.json").is_file():
        raise ValueError("This case finished; there is nothing to re-run.")
    status = _load(folder / "status.json")
    rerun = status.get("rerun") if status else None
    if not isinstance(rerun, dict) or not rerun.get("evidence"):
        raise ValueError("This interrupted case was created by an older version that did not record its "
                         "evidence path. Start a new analysis with the same evidence instead.")
    options = {key: rerun.get(key) for key in RERUN_KEYS}
    if not Path(options["evidence"]).exists():
        raise ValueError(f"The original evidence is no longer available at {options['evidence']}.")
    for key, label in (("yara_rules", "YARA rules"), ("iocs", "indicators file")):
        if options[key] and not Path(options[key]).is_file():
            raise ValueError(f"The {label} used by this case is no longer available at {options[key]}.")
    return options


def list_cases(data_dir, query=""):
    """Summaries of all cases under data_dir, newest first, optionally filtered by text."""
    data_dir = Path(data_dir)
    if not data_dir.is_dir():
        return []
    rows = []
    for folder in data_dir.iterdir():
        if not folder.is_dir():
            continue
        summary = case_summary(folder)
        if summary is None:
            continue
        if query and not _matches(query, summary["case_id"], summary["status"], summary["evidence"]):
            continue
        rows.append(summary)
    return sorted(rows, key=lambda row: (row["started_utc"], row["case_id"]), reverse=True)


def archive_dir(data_dir):
    return Path(data_dir) / ARCHIVE_FOLDER


def list_archived(data_dir, query=""):
    return list_cases(archive_dir(data_dir), query)


def _case_folder(folder, parent):
    """Resolve a case folder and require it to be a direct child of parent (no traversal, no links)."""
    folder, parent = Path(folder), Path(parent).resolve()
    if folder.is_symlink():
        raise ValueError("Case folder cannot be a link")
    resolved = folder.resolve()
    if resolved.parent != parent or not resolved.is_dir() or resolved.name == ARCHIVE_FOLDER:
        raise ValueError(f"Not a case folder inside {parent}")
    if case_summary(resolved) is None:
        raise ValueError("Folder does not contain a Mobile DF case")
    return resolved


def _move(folder, source_parent, destination_parent):
    source = _case_folder(folder, source_parent)
    destination_parent = Path(destination_parent)
    destination_parent.mkdir(parents=True, exist_ok=True)
    target = destination_parent / source.name
    if target.exists():
        raise ValueError(f"A case folder named {source.name} already exists in {destination_parent}")
    shutil.move(str(source), str(target))
    return target


def archive_case(data_dir, folder):
    """Move a case out of the active list into data_dir/_archive. Nothing is deleted."""
    return _move(folder, data_dir, archive_dir(data_dir))


def restore_case(data_dir, folder):
    """Move an archived case back into the active case list."""
    return _move(folder, archive_dir(data_dir), data_dir)


def delete_case(data_dir, folder):
    """Permanently delete a case workspace (its copies, logs and reports) from data_dir or its archive.

    Original evidence is never inside a case folder, so it is not affected.
    """
    data_dir = Path(data_dir)
    try:
        target = _case_folder(folder, data_dir)
    except ValueError:
        target = _case_folder(folder, archive_dir(data_dir))
    def clear_readonly(function, path, _error):
        # Verified working copies can keep the evidence's read-only attribute on Windows.
        os.chmod(path, stat.S_IWRITE)
        function(path)

    handler = "onexc" if sys.version_info >= (3, 12) else "onerror"
    shutil.rmtree(target, **{handler: clear_readonly})
    return target


def load_case(folder):
    """Full results for a case folder. Raises ValueError if the case has no readable results."""
    result = _load(Path(folder) / "results.json")
    if result is None:
        raise ValueError("This case has no readable results.json; it may have been interrupted.")
    return result


def _matches(query, *values):
    needle = query.strip().lower()
    return not needle or any(needle in str(value).lower() for value in values if value is not None)


def finding_text(finding):
    detail = finding.get("detail")
    if isinstance(detail, dict):
        for key in ("rule", "table", "warning", "error", "indicator", "message"):
            if detail.get(key):
                return f"{key}: {detail[key]}"
        if isinstance(detail.get("values"), dict):
            return ", ".join(f"{k}={v}" for k, v in list(detail["values"].items())[:4])
    return json.dumps(detail, ensure_ascii=False)[:200]


def filter_findings(findings, source="", severity="", query="", include_inventory=False):
    """Filter findings by exact source/severity and free-text search across path, kind and detail."""
    rows = []
    for item in findings or []:
        if not include_inventory and item.get("source") == "inventory" and source != "inventory":
            continue
        if source and item.get("source") != source:
            continue
        if severity and item.get("severity") != severity:
            continue
        if query and not _matches(query, item.get("path"), item.get("kind"), item.get("id"),
                                  json.dumps(item.get("detail"), ensure_ascii=False)):
            continue
        rows.append(item)
    return sorted(rows, key=lambda f: (SEVERITY_ORDER.get(f.get("severity"), 9), f.get("source", ""),
                                       f.get("timestamp") or "", f.get("id", "")))


def filter_timeline(timeline, start="", end="", query=""):
    """Timeline events between ISO start/end prefixes (inclusive) matching optional text."""
    rows = []
    for item in timeline or []:
        stamp = item.get("timestamp") or ""
        if start and stamp < start:
            continue
        if end and stamp[:len(end)] > end:
            continue
        if query and not _matches(query, item.get("path"), item.get("kind"), item.get("source"),
                                  json.dumps(item.get("detail"), ensure_ascii=False)):
            continue
        rows.append(item)
    return rows


def facets(findings):
    """Distinct sources and severities, for filter menus."""
    sources = sorted({f.get("source", "") for f in findings or [] if f.get("source")})
    severities = sorted({f.get("severity", "") for f in findings or [] if f.get("severity")},
                        key=lambda s: SEVERITY_ORDER.get(s, 9))
    return sources, severities


def _csv_safe(value):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False) if value is not None else ""
    return "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text


def export_findings_csv(findings, destination):
    """Write the given (already filtered) findings to CSV, neutralizing spreadsheet formulas."""
    destination = Path(destination)
    with destination.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["finding_id", "source", "kind", "severity", "timestamp_utc", "path", "summary"])
        for item in findings:
            writer.writerow([_csv_safe(v) for v in (item.get("id"), item.get("source"), item.get("kind"),
                                                    item.get("severity"), item.get("timestamp"),
                                                    item.get("path"), finding_text(item))])
    return destination
