"""Read-only case library used by the desktop workbench.

Loads saved case results, summarizes them for the case list, and filters
findings and timeline events for in-app review. Nothing here modifies a case.
"""
import csv
import json
from pathlib import Path

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
        return {"folder": str(folder), "case_id": status.get("case_id", folder.name),
                "status": "incomplete", "started_utc": "", "completed_utc": "",
                "findings": 0, "timeline_events": 0, "correlations": 0,
                "integrity": "unknown", "evidence": "", "report": None}
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
