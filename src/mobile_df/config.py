import importlib.util
import importlib.metadata
import json
import shutil
import sys
from pathlib import Path

from .core import TOOL_NAMES

DEFAULTS = {"aleapp": ["aleapp", "aleapp.exe"], "mvt": ["mvt-android"],
            "exiftool": ["exiftool"], "sleuthkit": ["fls"],
            "plaso": ["log2timeline.py", "log2timeline"], "psort": ["psort.py", "psort"],
            "tsk_recover": ["tsk_recover"]}


def load_config(path=None):
    path = Path(path) if path else Path("tools.local.json")
    config = json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else {}
    if not isinstance(config, dict) or not isinstance(config.get("commands", {}), dict):
        raise ValueError("Tool config must contain a commands object")
    for key, command in config.get("commands", {}).items():
        if key not in DEFAULTS or not isinstance(command, list) or not command or not all(isinstance(v, str) and v for v in command):
            raise ValueError(f"Invalid command configuration for {key}")
    return config


def command_for(name, config):
    command = config.get("commands", {}).get(name)
    if command:
        first = command[0]
        executable = shutil.which(first) or (str(Path(first).resolve()) if Path(first).is_file() else None)
        return [executable, *command[1:]] if executable else None
    if name == "mvt" and importlib.util.find_spec("mvt"):
        return [sys.executable, "-m", "mobile_df.mvt_worker"]
    for candidate in DEFAULTS.get(name, []):
        executable = shutil.which(candidate)
        if not executable:
            for suffix in ("", ".exe"):
                path = Path(sys.executable).parent / (candidate + suffix)
                if path.is_file():
                    executable = str(path)
                    break
        if executable:
            return [sys.executable, executable] if executable.endswith(".py") else [executable]
    return None


def doctor(config=None):
    config = config or {}
    result = {}
    for name in TOOL_NAMES:
        if name == "sqlite":
            import sqlite3
            result[name] = {"available": True, "backend": "Python sqlite3", "version": sqlite3.sqlite_version}
        elif name == "yara":
            ready = importlib.util.find_spec("yara") is not None
            result[name] = {"available": ready, "backend": "yara-python", "hint": "pip install yara-python"}
            if ready:
                result[name]["version"] = importlib.metadata.version("yara-python")
        else:
            command = command_for(name, config)
            available = bool(command) and (name != "plaso" or bool(command_for("psort", config)))
            result[name] = {"available": available, "command": command,
                            "hint": "Set commands in tools.local.json or add executables to PATH"}
            if name == "mvt" and importlib.util.find_spec("mvt"):
                result[name]["version"] = importlib.metadata.version("mvt")
    return result
