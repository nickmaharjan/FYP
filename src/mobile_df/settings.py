"""Persistent desktop analysis settings (stored as local JSON, never in Git)."""
import json
from pathlib import Path

from .core import TOOL_NAMES, write_json

DEFAULTS = {
    "data_dir": "data/cases",
    "timeout": 300,
    "max_rows": 1000,
    "image_offset": 0,
    "yara_rules": "",
    "iocs": "",
    # None means "every installed tool"; otherwise a list of tool names to pre-select.
    "default_tools": None,
}
LIMITS = {"timeout": (1, 86400), "max_rows": (1, 1_000_000), "image_offset": (0, 2**40)}


def validate(values):
    """Return (clean_settings, errors). Unknown keys are dropped; bad values are reported, not guessed."""
    clean, errors = dict(DEFAULTS), []
    for key, (low, high) in LIMITS.items():
        raw = values.get(key, DEFAULTS[key])
        try:
            number = int(str(raw).strip())
        except (TypeError, ValueError):
            errors.append(f"{key.replace('_', ' ').capitalize()} must be a whole number")
            continue
        if not low <= number <= high:
            errors.append(f"{key.replace('_', ' ').capitalize()} must be between {low} and {high}")
            continue
        clean[key] = number
    data_dir = str(values.get("data_dir") or "").strip()
    if not data_dir:
        errors.append("Case data folder is required")
    else:
        clean["data_dir"] = data_dir
    for key, label in (("yara_rules", "YARA rules file"), ("iocs", "Indicators file")):
        path = str(values.get(key) or "").strip()
        if path and not Path(path).is_file():
            errors.append(f"{label} does not exist: {path}")
        else:
            clean[key] = path
    tools = values.get("default_tools", DEFAULTS["default_tools"])
    if tools is not None:
        unknown = [name for name in tools if name not in TOOL_NAMES]
        if unknown:
            errors.append("Unknown tools: " + ", ".join(unknown))
        else:
            clean["default_tools"] = [name for name in TOOL_NAMES if name in tools]
    return clean, errors


def load_settings(path):
    """Load settings, falling back to defaults for a missing, unreadable or invalid file/key."""
    try:
        stored = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return dict(DEFAULTS)
    if not isinstance(stored, dict):
        return dict(DEFAULTS)
    clean, errors = validate({**DEFAULTS, **stored})
    if errors:
        # Keep every valid key; reset only the invalid ones.
        for key in DEFAULTS:
            single, bad = validate({**DEFAULTS, key: stored.get(key, DEFAULTS[key])})
            clean[key] = single[key] if not bad else DEFAULTS[key]
    return clean


def save_settings(path, values):
    """Validate and save. Raises ValueError listing every problem; nothing is written on error."""
    clean, errors = validate(values)
    if errors:
        raise ValueError("\n".join(errors))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, clean)
    return clean


def selected_tools(settings, availability):
    """Installed tools to pre-select for a new case, honouring the saved default selection."""
    installed = [name for name in TOOL_NAMES if availability.get(name, {}).get("available")]
    wanted = settings.get("default_tools")
    return installed if wanted is None else [name for name in installed if name in wanted]
