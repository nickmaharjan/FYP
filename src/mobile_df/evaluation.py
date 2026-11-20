"""Compare a finished case with a controlled fixture's expected findings.

The synthetic demo writes ``expected.json`` next to its evidence. This module
turns those expectations into explicit, repeatable checks so a case can be
scored without reading the report by hand. A check is only scored when the
tools it depends on actually ran; otherwise it is reported as ``skipped`` with
the reason, so missing tools never look like passes or failures.
"""
import json
from pathlib import Path, PurePosixPath

from .core import utc_now

RAN = {"success", "partial"}
STATUSES = ("pass", "fail", "skipped", "unsupported")


def load_case(path):
    """Accept a case directory or a results.json path."""
    path = Path(path)
    if path.is_dir():
        path = path / "results.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _runs(result):
    return {run["tool"]: run for run in result.get("tool_runs", [])}


def _not_run(runs, tools):
    """Return a skip reason when any required tool did not run."""
    missing = []
    for tool in tools:
        run = runs.get(tool)
        status = run["status"] if run else "absent"
        if status not in RAN:
            missing.append(f"{tool} {status}")
    return ("Required tool did not run: " + ", ".join(missing)) if missing else None


def _findings(result, source, kind=None):
    return [f for f in result.get("findings", [])
            if f.get("source") == source and (kind is None or f.get("kind") == kind)]


def _count_sqlite_databases(result):
    return len({f["path"] for f in _findings(result, "sqlite", "database_table")})


def _count_sqlite_sms_rows(result):
    return sum(1 for f in _findings(result, "sqlite", "database_row") if f["detail"].get("table") == "sms")


def _count_mvt_sms_rows(result):
    return sum(1 for f in _findings(result, "mvt", "mobile_artifact")
               if PurePosixPath(f.get("provenance", {}).get("output", "")).stem == "sms")


def _yara_rules(result):
    return sorted({f["detail"].get("rule") for f in _findings(result, "yara", "rule_match")})


def _count_media(result):
    return len(_findings(result, "exiftool", "metadata"))


def _image_files(result):
    return sorted({PurePosixPath(f["path"]).name for f in _findings(result, "sleuthkit", "filesystem_entry")})


def _url_sources(result, url):
    return sorted({source for c in result.get("correlations", [])
                   if c.get("type") == "url" and c.get("value") == url for source in c.get("sources", [])})


def _sqlite_tables(result):
    """``path::table`` -> database_table detail for every table the SQLite adapter reported."""
    return {f"{f['path']}::{f['detail'].get('table')}": f["detail"] for f in _findings(result, "sqlite", "database_table")}


def _row_present(result, table, values):
    path, _, name = table.rpartition("::")
    return any(f["path"] == path and f["detail"].get("table") == name
               and all(f["detail"].get("values", {}).get(k) == v for k, v in values.items())
               for f in _findings(result, "sqlite", "database_row"))


def _check(key, expected, result, runs):
    """Return (tools, description, observed, passed) or None for unknown keys."""
    kind = result.get("evidence_kind")
    if key == "sqlite_database_files":
        observed = _count_sqlite_databases(result)
        return ["sqlite"], "SQLite databases discovered", observed, observed == expected
    if key == "sqlite_sms_rows":
        observed = _count_sqlite_sms_rows(result)
        return ["sqlite"], "SMS rows exported by SQLite", observed, observed == expected
    if key == "mvt_sms_rows":
        observed = _count_mvt_sms_rows(result)
        return ["mvt"], "SMS records parsed by MVT", observed, observed == expected
    if key == "yara_rule":
        observed = _yara_rules(result)
        return ["yara"], "YARA rule matched", observed, expected in observed
    if key == "media_files":
        observed = _count_media(result)
        return ["exiftool"], "Media files with ExifTool metadata", observed, observed == expected
    if key == "image_file":
        if kind != "image":
            return "skip", f"Applies to image evidence; this case is {kind}"
        observed = _image_files(result)
        wanted = expected.lower()
        return ["sleuthkit"], "File listed from the filesystem image", observed, any(n.lower() == wanted for n in observed)
    if key == "image_file_time":
        if kind != "image":
            return "skip", f"Applies to image evidence; this case is {kind}"
        wanted, date = expected["file"].lower(), expected["date"]
        observed = sorted({f["timestamp"] for f in _findings(result, "sleuthkit", "file_time")
                           if PurePosixPath(f["path"]).name.lower() == wanted})
        return (["sleuthkit"], "File modification date recovered from the image timeline", observed,
                any(stamp.startswith(date) for stamp in observed))
    if key == "parameters":
        used = result.get("parameters", {})
        observed = {name: used.get(name) for name in expected}
        return [], "Case analysed with the parameters the fixture expects", observed, observed == expected
    if key == "tool_status":
        observed = {tool: runs.get(tool, {}).get("status", "absent") for tool in expected}
        return [], "Tool run status", observed, observed == expected
    if key == "sqlite_table_rows":
        tables = _sqlite_tables(result)
        observed = {name: (tables[name].get("rows") if name in tables else "missing") for name in expected}
        return ["sqlite"], "Exact row count per table", observed, observed == expected
    if key == "sqlite_truncated_tables":
        observed = sorted(name for name, detail in _sqlite_tables(result).items() if detail.get("truncated"))
        return ["sqlite"], "Tables cut off at the row limit", observed, observed == sorted(expected)
    if key == "sqlite_row_values":
        missing = [item for item in expected if not _row_present(result, item["table"], item["values"])]
        observed = {"found": len(expected) - len(missing), "missing": missing}
        return ["sqlite"], "Specific row values exported", observed, not missing
    if key == "shared_url":
        url_tools = [t for t in ("sqlite", "aleapp", "mvt") if runs.get(t, {}).get("status") in RAN]
        if len(url_tools) < 2:
            return "skip", "Needs at least two of sqlite, aleapp and mvt to run; ran: " + (", ".join(url_tools) or "none")
        observed = _url_sources(result, expected)
        return url_tools, "URL correlated across tools", observed, len(observed) >= 2
    return None


def evaluate(result, expected):
    """Score a case result dictionary against an expectations dictionary."""
    runs = _runs(result)
    checks = []
    integrity = result.get("integrity", {}).get("status")
    checks.append({"id": "integrity", "description": "Original evidence unchanged after analysis",
                   "expected": "verified", "observed": integrity,
                   "status": "pass" if integrity == "verified" else "fail"})
    for key, value in expected.items():
        if key == "description":
            continue
        entry = {"id": key, "expected": value}
        outcome = _check(key, value, result, runs)
        if outcome is None:
            entry.update(status="unsupported", reason="No evaluator exists for this expectation")
        elif outcome[0] == "skip":
            entry.update(status="skipped", reason=outcome[1])
        else:
            tools, description, observed, passed = outcome
            entry.update(description=description, tools=tools)
            reason = _not_run(runs, tools)
            if reason:
                entry.update(status="skipped", reason=reason)
            else:
                entry.update(observed=observed, status="pass" if passed else "fail")
        checks.append(entry)
    counts = {status: sum(c["status"] == status for c in checks) for status in STATUSES}
    scored = counts["pass"] + counts["fail"]
    # Integrity alone does not make a fixture evaluation meaningful.
    if counts["fail"]:
        verdict = "fail"
    elif counts["pass"] > 1:
        verdict = "pass"
    else:
        verdict = "inconclusive"
    return {"schema_version": 1, "case_id": result.get("case_id"), "case_status": result.get("status"),
            "evaluated_utc": utc_now(), "verdict": verdict, "summary": counts,
            "score": round(counts["pass"] / scored, 4) if scored else None,
            "fixture_description": expected.get("description"), "checks": checks,
            "note": "Controlled-fixture check only; it does not measure accuracy on real evidence."}


def evaluate_case(case, expected_path):
    expected = json.loads(Path(expected_path).read_text(encoding="utf-8"))
    if not isinstance(expected, dict):
        raise ValueError("Expected findings must be a JSON object")
    return evaluate(load_case(case), expected)
