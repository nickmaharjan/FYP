"""Repeatable controlled evaluation: run the synthetic fixtures several times and report accuracy and speed.

Each repetition analyses four controlled cases built by ``mobile_df.demo``:

* extraction - the Android-shaped folder, with every installed tool selected
* archive    - the same folder as a ZIP export, unpacked into the case before analysis
* backup     - an unencrypted Android backup (.ab) of the SMS app, checked by MVT
* image      - the FAT12 disk image, with The Sleuth Kit and YARA

Both are scored against the fixture's ``expected.json`` (see ``mobile_df.evaluation``).
The output folder receives ``benchmark.json`` (all numbers) and ``benchmark.md``
(tables ready for the evaluation chapter). Results describe these small synthetic
fixtures on this machine only; they are not accuracy claims about real evidence.

    python -m mobile_df.benchmark --output bench-2026-11-18 --runs 3
"""
import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path

from .config import doctor, load_config
from .core import TOOL_NAMES, utc_now, write_json
from .demo import create_demo
from .evaluation import evaluate
from .pipeline import analyze

RAN = {"success", "partial"}


def _stats(values):
    values = [v for v in values if v is not None]
    if not values:
        return None
    return {"mean": round(statistics.mean(values), 3), "min": round(min(values), 3), "max": round(max(values), 3),
            "runs": len(values)}


def run_benchmark(output, runs=3, config=None, progress=None):
    output = Path(output).resolve()
    if output.exists():
        raise ValueError("Benchmark output already exists; choose a new folder")
    if runs < 1:
        raise ValueError("Runs must be at least 1")
    config = load_config(config) if not isinstance(config, dict) else config
    available = [name for name, state in doctor(config).items() if state["available"]]
    fixture = create_demo(output / "fixture")
    expected = json.loads((output / "fixture" / "expected.json").read_text(encoding="utf-8"))
    cases = {
        "extraction": {"evidence": fixture["evidence"], "tools": [t for t in TOOL_NAMES if t in available and t != "sleuthkit"],
                       "extra": {"yara_rules": fixture["yara_rules"], "iocs": fixture["iocs"]}},
        "archive": {"evidence": output / "fixture" / "training-extraction.zip",
                    "tools": [t for t in TOOL_NAMES if t in available and t != "sleuthkit"],
                    "extra": {"yara_rules": fixture["yara_rules"], "iocs": fixture["iocs"]}},
        # YARA is not run on the backup: its content is zlib-compressed, so byte rules cannot match.
        "backup": {"evidence": output / "fixture" / "training-backup.ab",
                   "tools": [t for t in ("mvt",) if t in available], "extra": {"iocs": fixture["iocs"]}},
        "image": {"evidence": output / "fixture" / "training-fat12.img",
                  "tools": [t for t in ("sleuthkit", "yara") if t in available],
                  "extra": {"yara_rules": fixture["yara_rules"]}},
    }
    records = []
    for repetition in range(1, runs + 1):
        for name, case in cases.items():
            if not case["tools"]:
                continue   # e.g. the backup case needs MVT
            if progress:
                progress(f"Run {repetition}/{runs}: {name}")
            started = time.perf_counter()
            result = analyze(case["evidence"], output / "cases" / f"{name}-{repetition}", f"BENCH-{name}-{repetition}",
                             tools=case["tools"], config=config, **case["extra"])
            wall = time.perf_counter() - started
            evaluation = evaluate(result, expected)
            write_json(output / "cases" / f"{name}-{repetition}" / "evaluation.json", evaluation)
            records.append({"case": name, "run": repetition, "status": result["status"], "wall_seconds": round(wall, 3),
                            "pipeline_seconds": result["duration_seconds"], "metrics": result["metrics"],
                            "verdict": evaluation["verdict"], "summary": evaluation["summary"],
                            "checks": {c["id"]: c["status"] for c in evaluation["checks"]},
                            "tools": {r["tool"]: {"status": r["status"], "seconds": r.get("duration_seconds"),
                                                  "findings": r["findings_count"], "version": r.get("tool_version")}
                                      for r in result["tool_runs"] if r["status"] != "disabled"}})
    summary = {}
    for name, case in cases.items():
        if not case["tools"]:
            continue
        mine = [r for r in records if r["case"] == name]
        checks = {}
        for record in mine:
            for check, status in record["checks"].items():
                checks.setdefault(check, []).append(status)
        tools = {}
        for record in mine:
            for tool, info in record["tools"].items():
                tools.setdefault(tool, {"status": [], "seconds": [], "findings": [], "version": info["version"]})
                tools[tool]["status"].append(info["status"])
                tools[tool]["seconds"].append(info["seconds"])
                tools[tool]["findings"].append(info["findings"])
        passed = sum(s == "pass" for v in checks.values() for s in v)
        scored = sum(s in ("pass", "fail") for v in checks.values() for s in v)
        summary[name] = {
            "tools_selected": case["tools"], "wall_seconds": _stats([r["wall_seconds"] for r in mine]),
            "findings": _stats([r["metrics"]["findings"] for r in mine]),
            "timeline_events": _stats([r["metrics"]["timeline_events"] for r in mine]),
            "correlations": _stats([r["metrics"]["correlations"] for r in mine]),
            "verdicts": [r["verdict"] for r in mine], "check_pass_rate": round(passed / scored, 4) if scored else None,
            "checks": {check: sorted(set(statuses)) for check, statuses in checks.items()},
            "consistent_findings": len({r["metrics"]["findings"] for r in mine}) == 1,
            "tools": {tool: {"version": t["version"], "statuses": sorted(set(t["status"])),
                             "seconds": _stats(t["seconds"]), "findings": _stats(t["findings"])}
                      for tool, t in tools.items()},
        }
    report = {"schema_version": 1, "generated_utc": utc_now(), "runs": runs,
              "machine": {"platform": platform.platform(), "python": platform.python_version(),
                          "processor": platform.processor() or platform.machine()},
              "available_tools": available, "summary": summary, "records": records,
              "note": "Synthetic controlled fixtures on one machine; not an accuracy measure for real evidence."}
    write_json(output / "benchmark.json", report)
    (output / "benchmark.md").write_text(markdown(report), encoding="utf-8")
    return report


def markdown(report):
    lines = [f"# Controlled evaluation ({report['generated_utc'][:10]})", "",
             f"Machine: {report['machine']['platform']}, Python {report['machine']['python']}. "
             f"Repetitions: {report['runs']}. Installed tools: {', '.join(report['available_tools'])}.", "",
             "| Case | Verdicts | Check pass rate | Wall time mean (min-max) s | Findings | Timeline events | Same findings every run |",
             "|---|---|---|---|---|---|---|"]
    for name, item in report["summary"].items():
        wall = item["wall_seconds"]
        rate = "-" if item["check_pass_rate"] is None else f"{item['check_pass_rate']:.0%}"
        lines.append(f"| {name} | {', '.join(item['verdicts'])} | {rate} | "
                     f"{wall['mean']} ({wall['min']}-{wall['max']}) | {item['findings']['mean']} | "
                     f"{item['timeline_events']['mean']} | {'yes' if item['consistent_findings'] else 'no'} |")
    for name, item in report["summary"].items():
        lines += ["", f"## {name}: checks", "", "| Check | Outcome |", "|---|---|"]
        lines += [f"| {check} | {', '.join(statuses)} |" for check, statuses in item["checks"].items()]
        lines += ["", f"## {name}: tools", "", "| Tool | Version | Status | Mean seconds | Mean findings |", "|---|---|---|---|---|"]
        for tool, info in item["tools"].items():
            seconds = info["seconds"]["mean"] if info["seconds"] else "-"
            lines.append(f"| {tool} | {info['version'] or '-'} | {', '.join(info['statuses'])} | {seconds} | "
                         f"{info['findings']['mean']} |")
    lines += ["", report["note"], ""]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m mobile_df.benchmark", description="Controlled fixture benchmark")
    parser.add_argument("--output", type=Path, required=True, help="New folder for fixtures, cases and the report")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run_benchmark(args.output, args.runs, args.config,
                               progress=lambda message: print(message, file=sys.stderr, flush=True))
    except (OSError, ValueError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(markdown(report))
    failed = any(v == "fail" for item in report["summary"].values() for v in item["verdicts"])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
