import argparse
import json
import sys
from pathlib import Path

from .pipeline import analyze
from .config import doctor, load_config
from .core import TOOL_NAMES


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in {"analyze", "serve", "doctor", "demo", "--help", "-h"}:
        argv.insert(0, "analyze")
    parser = argparse.ArgumentParser(description="Local Android forensic orchestration")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze_parser = commands.add_parser("analyze", help="Analyze acquired evidence")
    analyze_parser.add_argument("evidence", type=Path)
    analyze_parser.add_argument("--output", type=Path, required=True)
    analyze_parser.add_argument("--case-id", default="case-001")
    analyze_parser.add_argument("--yara-rules", type=Path)
    analyze_parser.add_argument("--iocs", type=Path, help="MVT STIX2 indicators")
    analyze_parser.add_argument("--timeout", type=int, default=300)
    analyze_parser.add_argument("--config", type=Path)
    analyze_parser.add_argument("--tools", nargs="+", choices=TOOL_NAMES)
    analyze_parser.add_argument("--kind", choices=["auto", "directory", "archive", "image", "backup"], default="auto")
    analyze_parser.add_argument("--mvt-mode", choices=["auto", "backup", "bugreport", "androidqf"], default="auto")
    analyze_parser.add_argument("--max-rows", type=int, default=1000)
    analyze_parser.add_argument("--max-findings", type=int, default=50000)
    analyze_parser.add_argument("--max-extract-gb", type=float, default=20)
    analyze_parser.add_argument("--image-offset", type=int, default=0)
    serve_parser = commands.add_parser("serve", help="Start local dashboard")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.add_argument("--data-dir", type=Path, default=Path("data/cases"))
    serve_parser.add_argument("--config", type=Path)
    doctor_parser = commands.add_parser("doctor", help="Check installed tool backends")
    doctor_parser.add_argument("--config", type=Path)
    demo_parser = commands.add_parser("demo", help="Generate synthetic evidence and analyze it")
    demo_parser.add_argument("--output", type=Path, required=True, help="New demo directory")
    demo_parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            print(json.dumps(doctor(load_config(args.config)), indent=2))
            return 0
        if args.command == "serve":
            from .server import serve
            serve(args.data_dir, args.config, args.port)
            return 0
        if args.command == "demo":
            from .demo import create_demo
            fixture = create_demo(args.output / "fixture")
            output = args.output / "case"
            result = analyze(**fixture, output=output, case_id="SYNTHETIC-DEMO", config=args.config,
                             progress=lambda message: print(message, file=sys.stderr, flush=True))
        else:
            options = vars(args).copy()
            options.pop("command")
            output = args.output
            result = analyze(**options, progress=lambda message: print(message, file=sys.stderr, flush=True))
    except (OSError, ValueError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(json.dumps({"case": result["case_id"], "status": result["status"], "report": str(output.resolve() / "report.html"),
                      "metrics": result["metrics"]}, indent=2))
    return 1 if result["status"] in {"failed", "cancelled"} else 0


if __name__ == "__main__":
    sys.exit(main())
