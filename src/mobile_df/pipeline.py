"""Case lifecycle: verified working copy -> adapters -> correlation -> exports."""
import csv
import json
import shutil
import time
from pathlib import Path

from .adapters import ADAPTERS, Context
from .config import doctor, load_config
from .core import TOOL_NAMES, artifact, correlate, sha256, utc_now, write_json
from .evidence import detect_kind, inventory, is_link, stage
from .report import render_report


def analyze(evidence, output, case_id="case-001", yara_rules=None, timeout=300, *,
            config=None, tools=None, iocs=None, kind="auto", mvt_mode="auto",
            max_rows=1000, max_findings=50000, max_extract_gb=20, image_offset=0,
            progress=None, cancel=None):
    evidence = Path(evidence).absolute()
    if is_link(evidence):
        raise ValueError("Evidence root cannot be a symbolic link or reparse point")
    evidence = evidence.resolve(strict=True)
    output = Path(output).resolve()
    selected = set(TOOL_NAMES if tools is None else tools)
    if selected - set(TOOL_NAMES):
        raise ValueError("Unknown tool: " + ", ".join(sorted(selected - set(TOOL_NAMES))))
    if not case_id.strip() or any(c in case_id for c in "\r\n"):
        raise ValueError("Case ID must be nonempty and on one line")
    if timeout < 1 or max_rows < 1 or max_findings < 1 or max_extract_gb <= 0 or image_offset < 0:
        raise ValueError("Timeout and analysis limits must be positive; image offset must be nonnegative")
    if output == evidence or output in evidence.parents or evidence in output.parents:
        raise ValueError("Output must be separate from the evidence path")
    if output.exists():
        raise ValueError("Output directory already exists; choose a new case directory")
    if kind not in ("auto", "directory", "archive", "image", "backup"):
        raise ValueError("Invalid evidence kind")
    if mvt_mode not in ("auto", "backup", "bugreport", "androidqf"):
        raise ValueError("Invalid MVT mode")
    rules = Path(yara_rules).resolve(strict=True) if yara_rules else None
    indicators = Path(iocs).resolve(strict=True) if iocs else None
    for path in (rules, indicators):
        if path and not path.is_file():
            raise ValueError("Rules and indicators must be files")
    config = load_config(config) if not isinstance(config, dict) else config
    kind = detect_kind(evidence, kind)
    if (kind == "directory") != evidence.is_dir():
        raise ValueError("Evidence kind does not match the supplied path")
    output.mkdir(parents=True)
    start = time.monotonic()
    result = {"schema_version": 2, "case_id": case_id, "status": "running", "evidence": str(evidence),
              "evidence_kind": kind, "started_utc": utc_now(), "completed_utc": None,
              "inventory": [], "tool_availability": doctor(config), "tool_runs": [], "findings": [],
              "correlations": [], "timeline": [], "integrity": {"status": "pending"}, "warnings": [],
              "parameters": {"selected_tools": sorted(selected), "timeout": timeout, "max_rows": max_rows,
                             "max_findings_per_tool": max_findings, "max_extract_gb": max_extract_gb, "image_offset": image_offset},
              "limitations": ["A tool match is a lead requiring investigator review, not proof of compromise.",
                              "Timeline only normalizes recognized epoch values or explicit timezones; raw values remain in findings.",
                              "Image recovery covers allocated files at the specified sector offset; encrypted filesystems are not decrypted.",
                              "Prototype limits and tool compatibility can reduce coverage. Review tool logs and warnings."]}

    def notify(message):
        with (output / "audit.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"time": utc_now(), "message": message}) + "\n")
        if progress:
            progress(message)

    try:
        notify("Hashing original evidence")
        result["inventory"] = inventory(evidence)
        write_json(output / "manifest.json", result["inventory"])
        notify("Creating and verifying working copy")
        staged = stage(evidence, output, result["inventory"], kind, int(max_extract_gb * 1024**3))
        for item in result["inventory"]:
            result["findings"].append(artifact("inventory", "file", item["path"], item))
        for label, path in (("yara_rules", rules), ("iocs", indicators)):
            if path:
                folder = output / "inputs"
                folder.mkdir(exist_ok=True)
                destination = folder / (label + path.suffix)
                shutil.copy2(path, destination)
                result["parameters"][label] = {"original_path": str(path), "sha256": sha256(destination)}
                if label == "yara_rules":
                    rules = destination
                else:
                    indicators = destination
        ctx = Context(staged, output, kind, config, timeout, max_rows, max_findings,
                      rules, indicators, mvt_mode, image_offset, cancel)
        for adapter in ADAPTERS:
            run = {"tool": adapter.name, "status": "pending", "findings_count": 0, "steps": []}
            result["tool_runs"].append(run)
            reason = adapter.applicable(ctx)
            if adapter.name not in selected:
                run.update(status="disabled", reason="Not selected")
            elif cancel and cancel.is_set():
                run.update(status="cancelled", reason="Cancelled by investigator")
            elif reason:
                run.update(status="not_applicable", reason=reason)
            elif not result["tool_availability"][adapter.name]["available"]:
                run.update(status="unavailable", reason="Required executable or Python package is not installed/configured")
            else:
                notify(f"Running {adapter.name}")
                before = len(ctx.steps)
                tick = time.monotonic()
                try:
                    findings = adapter.run(ctx)
                    result["findings"].extend(findings)
                    run["findings_count"] = len(findings)
                    run["status"] = "success"
                    if any(f["kind"] == "analysis_warning" or f["detail"].get("truncated") for f in findings):
                        run.update(status="partial", reason="Analysis limits were reached; see findings and raw output")
                    if len(findings) >= max_findings:
                        run["status"] = "partial"
                        run["reason"] = "Finding limit reached; inspect raw output for remaining records"
                except Exception as exc:
                    run.update(status="failed", reason=f"{type(exc).__name__}: {exc}")
                run["steps"] = ctx.steps[before:]
                run["duration_seconds"] = round(time.monotonic() - tick, 3)
                for step in run["steps"]:
                    if step["status"] != "success":
                        run.update(status=step["status"], reason="Tool did not complete successfully; inspect logs")
                notify(f"{adapter.name}: {run['status']} ({run['findings_count']} findings)")
            write_json(output / "status.json", {"case_id": case_id, "tool_runs": result["tool_runs"]})
        notify("Verifying original evidence after analysis")
        after = inventory(evidence)
        result["integrity"] = {"status": "verified" if after == result["inventory"] else "changed",
                               "checked_utc": utc_now(), "method": "Full SHA-256, path, size and mtime comparison before and after analysis"}
        if after != result["inventory"]:
            result["warnings"].append("Original evidence changed during analysis; this case requires review")
        result["correlations"] = correlate(result["findings"])
        result["timeline"] = sorted([f for f in result["findings"] if f["timestamp"]], key=lambda f: (f["timestamp"], f["id"]))
        statuses = {run["status"] for run in result["tool_runs"]}
        result["status"] = "cancelled" if "cancelled" in statuses else "completed_with_warnings" if (
            statuses & {"failed", "timeout", "partial", "unavailable"} or result["warnings"]) else "completed"
    except Exception as exc:
        result["status"] = "failed"
        result["warnings"].append(f"{type(exc).__name__}: {exc}")
        notify(f"Case failed: {exc}")
    result["completed_utc"] = utc_now()
    result["duration_seconds"] = round(time.monotonic() - start, 3)
    attempted = [r for r in result["tool_runs"] if r["status"] in {"success", "failed", "timeout", "partial"}]
    result["metrics"] = {"files": len(result["inventory"]), "bytes": sum(i["size"] for i in result["inventory"]),
                         "findings": len(result["findings"]), "timeline_events": len(result["timeline"]),
                         "correlations": len(result["correlations"]), "tools_attempted": len(attempted),
                         "tools_successful": sum(r["status"] == "success" for r in attempted)}
    write_json(output / "results.json", result)
    with (output / "timeline.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["timestamp_utc", "source", "kind", "path", "finding_id", "timestamp_basis"])
        def csv_safe(value):
            text = str(value or "")
            return "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text
        writer.writerows([csv_safe(value) for value in [f["timestamp"], f["source"], f["kind"], f["path"], f["id"], f["timestamp_basis"]]] for f in result["timeline"])
    (output / "report.html").write_text(render_report(result), encoding="utf-8")
    notify(f"Case {result['status']}; report saved")
    return result
