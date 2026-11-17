"""Case handoff: package a finished case as one ZIP that a recipient can verify.

The ZIP holds the report and machine-readable results plus HANDOFF-MANIFEST.json,
which lists the SHA-256 and size of every packaged file. A `<zip>.sha256` file is
written next to the ZIP in the common `sha256sum` format. Evidence working copies
are never packaged; native tool output (which can include recovered files) is
only added when asked for.

Verify a received package:  python -m mobile_df.handoff verify CASE.zip
"""
import argparse
import hashlib
import json
import os
import re
import sys
import zipfile
from pathlib import Path

from .core import utc_now

CORE_FILES = ("report.html", "results.json", "timeline.csv", "manifest.json", "audit.jsonl")
ALWAYS_FOLDERS = ("logs", "inputs")      # subprocess logs; copies of the YARA rules / indicators used
OPTIONAL_FOLDERS = ("tools",)            # native tool output; may contain files recovered from evidence
NEVER_FOLDERS = ("working",)             # verified evidence working copies
MANIFEST_NAME = "HANDOFF-MANIFEST.json"
README_NAME = "HANDOFF-README.txt"


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_name(text):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._") or "case"


def _files_under(folder):
    for root, dirs, files in os.walk(folder, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not Path(root, d).is_symlink())
        for name in sorted(files):
            path = Path(root, name)
            if path.is_file() and not path.is_symlink():
                yield path


def default_filename(result):
    stamp = (result.get("completed_utc") or utc_now())[:10]
    return f"{_safe_name(result.get('case_id', 'case'))}-handoff-{stamp}.zip"


def export_case(case_folder, destination, include_tool_output=False):
    """Write a handoff ZIP for a finished case and return a summary of what was packaged."""
    case_folder = Path(case_folder).resolve()
    destination = Path(destination).resolve()
    results_path = case_folder / "results.json"
    try:
        result = json.loads(results_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError("Only finished cases can be handed off; this case has no readable results.json.")
    if destination.suffix.lower() != ".zip":
        raise ValueError("The handoff file name must end in .zip")
    if destination.exists():
        raise ValueError(f"{destination.name} already exists; choose a new file name.")
    if case_folder == destination.parent or case_folder in destination.parents:
        raise ValueError("Save the handoff ZIP outside the case folder.")

    selected = [case_folder / name for name in CORE_FILES if (case_folder / name).is_file()]
    for name in ALWAYS_FOLDERS + (OPTIONAL_FOLDERS if include_tool_output else ()):
        if (case_folder / name).is_dir() and not (case_folder / name).is_symlink():
            selected.extend(_files_under(case_folder / name))

    root = _safe_name(result.get("case_id", case_folder.name))
    entries = []
    temporary = destination.with_name(destination.name + ".partial")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in selected:
                relative = path.relative_to(case_folder).as_posix()
                archive.write(path, f"{root}/{relative}")
                entries.append({"path": relative, "size": path.stat().st_size, "sha256": _sha256_file(path)})
            manifest = {
                "format": "mobile-df-handoff", "format_version": 1, "exported_utc": utc_now(),
                "case_id": result.get("case_id"), "case_status": result.get("status"),
                "case_started_utc": result.get("started_utc"), "case_completed_utc": result.get("completed_utc"),
                "evidence_integrity": (result.get("integrity") or {}).get("status"),
                "evidence_files": len(result.get("inventory") or []),
                "metrics": result.get("metrics") or {},
                "included_tool_output": include_tool_output,
                "excluded": ["working/ (evidence working copies)"] + ([] if include_tool_output else
                            ["tools/ (native tool output; may contain recovered evidence files)"]),
                "files": entries,
                "note": "Original evidence SHA-256 values are in manifest.json. "
                        "Verify this package with: python -m mobile_df.handoff verify <zip>",
            }
            archive.writestr(f"{root}/{MANIFEST_NAME}", json.dumps(manifest, ensure_ascii=False, indent=2))
            archive.writestr(f"{root}/{README_NAME}", _readme(manifest))
        temporary.replace(destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    zip_hash = _sha256_file(destination)
    sidecar = destination.with_name(destination.name + ".sha256")
    sidecar.write_text(f"{zip_hash}  {destination.name}\n", encoding="utf-8")
    return {"zip": str(destination), "sha256": zip_hash, "sha256_file": str(sidecar),
            "files": len(entries), "bytes": destination.stat().st_size,
            "included_tool_output": include_tool_output}


def _readme(manifest):
    return (
        f"Mobile DF case handoff: {manifest['case_id']}\n"
        f"Case status: {manifest['case_status']}; evidence integrity: {manifest['evidence_integrity']}\n"
        f"Exported (UTC): {manifest['exported_utc']}\n\n"
        "Open report.html in a browser to review the case.\n\n"
        f"{MANIFEST_NAME} lists the SHA-256 of every file in this package.\n"
        "The .sha256 file delivered next to the ZIP holds the hash of the ZIP itself.\n"
        "To verify, run from the Mobile DF project:\n"
        "    python -m mobile_df.handoff verify <this zip>\n"
        "or on Windows check the ZIP hash with:\n"
        "    Get-FileHash <this zip> -Algorithm SHA256\n\n"
        "Not included: " + "; ".join(manifest["excluded"]) + "\n"
        "Findings are investigative leads that require review; see the report's limitations.\n"
    )


def verify_handoff(zip_path):
    """Check every packaged file against the manifest, and the ZIP against its .sha256 file if present."""
    zip_path = Path(zip_path)
    problems = []
    sidecar = zip_path.with_name(zip_path.name + ".sha256")
    zip_check = "no .sha256 file found"
    if sidecar.is_file():
        expected = sidecar.read_text(encoding="utf-8").split()[0].lower()
        zip_check = "match" if _sha256_file(zip_path) == expected else "MISMATCH"
        if zip_check != "match":
            problems.append("ZIP hash does not match its .sha256 file")
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
        manifests = [name for name in names if name.endswith("/" + MANIFEST_NAME)]
        if len(manifests) != 1:
            raise ValueError("Not a Mobile DF handoff package (manifest missing)")
        root = manifests[0][: -len(MANIFEST_NAME)]
        manifest = json.loads(archive.read(manifests[0]).decode("utf-8"))
        listed = set()
        for entry in manifest.get("files", []):
            name = root + entry["path"]
            listed.add(name)
            if name not in names:
                problems.append(f"missing: {entry['path']}")
                continue
            data = archive.read(name)
            if len(data) != entry["size"] or _sha256_bytes(data) != entry["sha256"]:
                problems.append(f"changed: {entry['path']}")
        for name in names:
            if name not in listed and name not in (root + MANIFEST_NAME, root + README_NAME) and not name.endswith("/"):
                problems.append(f"unexpected file: {name[len(root):]}")
    return {"ok": not problems, "case_id": manifest.get("case_id"), "files_checked": len(manifest.get("files", [])),
            "zip_hash": zip_check, "problems": problems}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m mobile_df.handoff", description="Case handoff packages")
    commands = parser.add_subparsers(dest="command", required=True)
    export_parser = commands.add_parser("export", help="Package a finished case as a handoff ZIP")
    export_parser.add_argument("case", type=Path, help="Case folder")
    export_parser.add_argument("zip", type=Path, help="New .zip file to create")
    export_parser.add_argument("--include-tool-output", action="store_true",
                               help="Also package native tool output (may contain recovered evidence files)")
    verify_parser = commands.add_parser("verify", help="Verify a received handoff ZIP")
    verify_parser.add_argument("zip", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "export":
            print(json.dumps(export_case(args.case, args.zip, args.include_tool_output), indent=2))
            return 0
        report = verify_handoff(args.zip)
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 1
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    sys.exit(main())
