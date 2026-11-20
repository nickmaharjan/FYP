"""First-run setup checklist shown on the desktop home screen (no GUI code here).

Each item says whether it is done, why it matters, and where to fix it. Items marked
``required`` block nothing, but the home screen keeps the checklist visible until they are done.
"""
import os
from pathlib import Path

PACK_TOOLS = ("sleuthkit", "exiftool", "aleapp")
PYTHON_TOOLS = ("yara", "mvt")


def setup_checklist(availability, settings, data_dir):
    missing_packs = [t for t in PACK_TOOLS if not availability.get(t, {}).get("available")]
    missing_python = [t for t in PYTHON_TOOLS if not availability.get(t, {}).get("available")]
    rules = str(settings.get("yara_rules") or "")
    data_dir = Path(data_dir)
    probe = data_dir if data_dir.exists() else next((p for p in data_dir.parents if p.exists()), data_dir)
    writable = probe.exists() and os.access(probe, os.W_OK)
    return [
        {"key": "tools", "required": True, "done": not missing_packs, "action": "tools",
         "title": "Install the forensic tool packs",
         "detail": "Missing: " + ", ".join(missing_packs) if missing_packs else "The Sleuth Kit, ExifTool and ALEAPP are installed."},
        {"key": "python", "required": True, "done": not missing_python, "action": "setup",
         "title": "Install YARA and MVT",
         "detail": ("Missing: " + ", ".join(missing_python) + ". Run scripts\\setup.ps1 once.") if missing_python
                   else "yara-python and MVT are installed."},
        {"key": "rules", "required": False, "done": bool(rules) and Path(rules).is_file(), "action": "settings",
         "title": "Choose a YARA rules file",
         "detail": "Without rules YARA is skipped in every case." if not rules else
                   ("Rules file not found: " + rules) if not Path(rules).is_file() else "YARA rules are set."},
        {"key": "storage", "required": True, "done": writable, "action": "settings",
         "title": "Case data folder is writable",
         "detail": f"Cases are saved in {data_dir}." if writable else f"Cannot write to {data_dir}; choose another folder."},
        {"key": "plaso", "required": False, "done": bool(availability.get("plaso", {}).get("available")), "action": "docs",
         "title": "Optional: Plaso super-timeline",
         "detail": "Set plaso_docker_image in tools.local.json (Docker) or Plaso commands. See docs/installation.md."},
    ]


def checklist_complete(items):
    return all(item["done"] for item in items if item["required"])
