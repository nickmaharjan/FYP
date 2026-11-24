"""Plain-language case overview: findings grouped by what they are, and tool outcomes in plain words.

An investigator thinks "show me the messages", not "show me SQLite rows". This module maps every
finding to one category (Messages, Calls, Contacts, ...) using only what the finding already
records (its tool, kind, path, ALEAPP report name, ExifTool file type or Plaso data type), and
builds the summary shown before any table. It is GUI-free so the desktop app, the HTML report and
tests can share it.
"""
import collections
import json
import re
from datetime import datetime
from pathlib import PurePosixPath

# (key, label, short explanation) in display order.
CATEGORIES = (
    ("messages", "Messages", "Texts, chats and emails"),
    ("calls", "Calls", "Call logs from the phone and apps"),
    ("contacts", "Contacts", "Address book and app contacts"),
    ("web", "Web & searches", "Browsing history, searches, downloads and cookies"),
    ("locations", "Locations", "Maps, places and trips"),
    ("media", "Photos & media", "Pictures, videos, audio and their details"),
    ("accounts", "Accounts", "Accounts signed in on the device"),
    ("apps", "Apps & usage", "Installed apps, programs run and how they were used"),
    ("device", "Device & settings", "System settings, connections and device events"),
    ("files", "Files & system", "File listings, file times and database structure"),
    ("leads", "Leads to check", "Rule matches, indicators and unusual timestamps worth a closer look"),
    ("problems", "Tool problems", "Files or tables a tool could not read"),
    ("evidence", "Evidence files", "The evidence files you supplied and their fingerprints"),
)
LABELS = {key: label for key, label, _ in CATEGORIES}
EXPLANATIONS = {key: text for key, _, text in CATEGORIES}
USER_ACTIVITY = ("messages", "calls", "contacts", "web", "locations", "media", "accounts", "apps")

# Keyword rules for ALEAPP report names, checked in order; first match wins. Calls and contacts
# come before messages so that "Line - Call Logs" or "Facebook Messenger - Contacts" land correctly.
_REPORT_RULES = (
    ("files", ("storage metadata",)),
    ("calls", ("call log", "call event", "voip call")),
    ("contacts", ("contact", "roster", "friends", "peer details", "- users")),
    ("accounts", ("account", "authentication token", "user id", "user session", "siminfo", "login data")),
    ("messages", ("message", "sms", "mms", "chat", "conversation", "email", "gmail", "threads", "keystroke")),
    ("locations", ("maps", "location", "trip", "place", "gps", "wifi")),
    ("web", ("browser", "chrome", "history", "bookmark", "cookie", "search", "download", "offline page",
             "network action predictor", "web")),
    ("media", ("photo", "gallery", "image", "media", "video", "audio", "attachment", "camera")),
    ("apps", ("installedapps", "package", "app ", "apps", "permission", "wellbeing", "usage", "time in app",
              "standby", "netstats", "battery", "dex ", "graphics stats", "runtimeperms", "ssaid", "fcm",
              "tiktok", "spotify", "frosting", "playlist")),
    ("device", ("setting", "os version", "boot", "factory reset", "bluetooth", "adb", "dropbox", "anr",
                "users and profiles", "magisk", "cast", "telecom", "psettings", "suggestion")),
)

# SQLite database file names and table names that identify common Android and browser stores.
_DATABASE_RULES = (
    ("calls", {"calllog.db"}, {"calls"}),
    ("contacts", {"contacts2.db", "contacts.db"}, {"raw_contacts", "contacts"}),
    ("messages", {"mmssms.db", "bugle_db", "msgstore.db", "icing_mmssms.db", "cache4.db", "threads_db2"},
     {"sms", "mms", "pdu", "messages", "message", "chat", "conversations"}),
    ("web", {"history", "web data", "cookies", "favicons", "top sites"}, {"urls", "visits", "keyword_search_terms"}),
    ("accounts", {"accounts.db", "accounts_ce.db", "accounts_de.db"}, {"accounts"}),
)

_PLASO_RULES = (
    ("web", ("msiecf", "chrome", "firefox", "safari", "edge", "opera", "browser", "cookie")),
    ("apps", ("windows:lnk", "userassist", "prefetch", "appcompatcache", "shell_item", "windows:registry:mrulist",
              "windows:registry:bagmru", "jump_list", "amcache", "srum")),
    ("messages", ("skype", "email", "imessage", "sms")),
    ("device", ("windows:evtx", "windows:evt", "windows:registry", "syslog", "setupapi", "task_scheduler")),
    ("media", ("exif", "image")),
)


def _report_name(finding):
    """ALEAPP stores each row's report as provenance.output, e.g. '.../_TSV Exports/SMS Messages.tsv'."""
    output = (finding.get("provenance") or {}).get("output") or ""
    return PurePosixPath(str(output).replace("\\", "/")).stem


def _match(text, rules):
    text = text.lower()
    for key, words in rules:
        if any(word in text for word in words):
            return key
    return None


def categorize(finding):
    """The category key for one finding. Every finding gets exactly one category."""
    source, kind = finding.get("source", ""), finding.get("kind", "")
    detail = finding.get("detail") if isinstance(finding.get("detail"), dict) else {}
    if source == "inventory":
        return "evidence"
    if kind in ("analysis_error", "analysis_warning"):
        return "problems"
    if kind in ("rule_match", "indicator", "timestamp_anomaly"):
        return "leads"
    if source == "aleapp":
        return _match(_report_name(finding), _REPORT_RULES) or "apps"
    if source == "mvt":
        module = str(detail.get("module") or _report_name(finding) or finding.get("path", ""))
        return _match(module, (("messages", ("sms", "mms", "whatsapp")), ("calls", ("call",)),
                               ("contacts", ("contact",)), ("web", ("chrome", "browser", "firefox")),
                               ("apps", ("package", "app", "process", "dumpsys")))) or "device"
    if source == "sqlite":
        if kind == "database_table":
            return "files"
        name = PurePosixPath(finding.get("path", "")).name.lower()
        table = str(detail.get("table", "")).lower()
        for key, names, tables in _DATABASE_RULES:
            if name in names:
                return key
        for key, names, tables in _DATABASE_RULES:
            if table in tables:
                return key
        return "files"
    if source == "exiftool":
        mime = str(detail.get("File:MIMEType") or detail.get("MIMEType") or "")
        return "media" if mime.split("/")[0] in ("image", "video", "audio") else "files"
    if source == "plaso":
        return _match(str(detail.get("data_type") or detail.get("parser") or ""), _PLASO_RULES) or "files"
    return "files"


def group_findings(findings):
    """{category key: [findings]} for every category that has findings, in display order."""
    groups = collections.defaultdict(list)
    for finding in findings or []:
        groups[categorize(finding)].append(finding)
    return {key: groups[key] for key, _, _ in CATEGORIES if groups.get(key)}


def filter_category(findings, category):
    return [f for f in findings or [] if categorize(f) == category] if category else list(findings or [])


PLAIN_STATUS = {
    "success": "Worked",
    "partial": "Worked, but not everything could be read",
    "failed": "Did not work",
    "timeout": "Stopped: it took longer than the time limit",
    "not_applicable": "Not used for this kind of evidence",
    "unavailable": "Not installed on this computer",
    "disabled": "Not selected for this case",
    "cancelled": "Cancelled by the investigator",
}


def plain_status(run):
    """One sentence describing a tool run, e.g. 'Worked, but not everything could be read: ...'."""
    status = run.get("status", "")
    text = PLAIN_STATUS.get(status, status.replace("_", " ").capitalize() or "Unknown")
    reason = run.get("reason") or ""
    if reason and status not in ("success", "disabled", "unavailable"):
        text += f". {reason}"
    return text


def _duration(result):
    try:
        start = datetime.fromisoformat(result["started_utc"])
        end = datetime.fromisoformat(result["completed_utc"])
    except (KeyError, TypeError, ValueError):
        return None
    seconds = int((end - start).total_seconds())
    return f"{seconds // 60} min {seconds % 60} s" if seconds >= 60 else f"{seconds} s"


def case_overview(result):
    """Everything the summary page shows, as plain data."""
    findings = result.get("findings") or []
    groups = group_findings(findings)
    runs = result.get("tool_runs") or []
    worked = [r for r in runs if r.get("status") in ("success", "partial")]
    broken = [r for r in runs if r.get("status") in ("failed", "timeout")]
    unused = [r for r in runs if r.get("status") in ("not_applicable", "unavailable")]
    integrity = (result.get("integrity") or {}).get("status", "unknown")

    # Times at or after the analysis started cannot come from the evidence (for example the
    # modification time of a freshly extracted working copy), so they are left out of the range.
    started = str(result.get("started_utc") or "9999")
    activity = [f for key in USER_ACTIVITY for f in groups.get(key, [])
                if f.get("timestamp") and str(f["timestamp"]) < started]
    days = collections.Counter(str(f["timestamp"])[:10] for f in activity)
    stamps = sorted(str(f["timestamp"]) for f in activity)

    attention = []
    if integrity != "verified":
        attention.append(f"Evidence integrity is {integrity}: the evidence may have changed during analysis.")
    for run in runs:
        if run.get("status") in ("failed", "timeout", "partial"):
            attention.append(f"{run.get('tool')}: {plain_status(run)}")
    if groups.get("leads"):
        attention.append(f"{len(groups['leads'])} lead(s) to check: rule matches, indicators or unusual timestamps. "
                         "These are not proof; review each one.")
    for warning in result.get("warnings") or []:
        if not any(warning in item for item in attention):
            attention.append(warning)

    kind = str(result.get("evidence_kind") or "evidence").replace("_", " ")
    duration = _duration(result)
    tools = [f"{len(worked)} tool{'s' if len(worked) != 1 else ''} produced results"]
    if broken:
        tools.append(f"{len(broken)} did not work")
    if unused:
        tools.append(f"{len(unused)} {'was' if len(unused) == 1 else 'were'} not used "
                     "(wrong evidence type or not installed)")
    headline = (f"This {kind} was analysed{' in ' + duration if duration else ''}. "
                + (", ".join(tools[:-1]) + " and " + tools[-1] if len(tools) > 1 else tools[0]) + ". "
                + ("The evidence was not changed by the analysis." if integrity == "verified"
                   else "Check the evidence integrity below."))
    if not any(key in groups for key in USER_ACTIVITY):
        attention.append("No user activity (messages, web history, apps used and so on) was found by the tools "
                         "that ran. For a phone extraction use ALEAPP; for a computer disk use Plaso.")
    return {
        "headline": headline,
        "integrity": integrity,
        "duration": duration,
        "categories": [{"key": key, "label": LABELS[key], "explanation": EXPLANATIONS[key], "count": len(items)}
                       for key, items in groups.items()],
        "activity_range": (stamps[0][:10], stamps[-1][:10]) if stamps else None,
        "busiest_days": days.most_common(3),
        "attention": attention,
        "tools": [{"tool": r.get("tool"), "status": r.get("status"), "plain": plain_status(r),
                   "findings": r.get("findings_count", 0)} for r in runs],
    }


# ----- Readable one-line descriptions ------------------------------------------------------------

_TAG = re.compile(r"<[^>]+>")
_SPACE = re.compile(r"\s+")
# Column names worth showing first, in order; anything that looks like a time is left out because
# the finding's own timestamp column already shows it.
_PREFERRED = ("display name", "name", "partner", "contact", "address", "phone number", "number", "from", "to",
              "sender", "recipient", "body", "message", "text", "title", "url", "query", "search", "subject",
              "account name", "account", "app", "package", "doc id", "location", "latitude", "longitude",
              "type", "direction", "duration", "filename", "source url")
_SKIP = ("time", "date", "timestamp", "source file", "source", "profile path", "record location", "row id",
         "msg id", "thread id", "contact id", "_id", "id", "password", "token", "mime type", "mimetype", "data")
_MACB = {"m": "modified", "a": "accessed", "c": "metadata changed", "b": "created"}
_SMS_TYPE = {1: "Received", 2: "Sent", 3: "Draft", 4: "Outbox", 5: "Failed", 6: "Queued"}
_CALL_TYPE = {1: "Incoming call", 2: "Outgoing call", 3: "Missed call", 4: "Voicemail", 5: "Rejected call",
              6: "Blocked call"}
MAX_TEXT = 220


def _clean(value, limit=90):
    """Display text for one value: no markup, single spaces, shortened."""
    if value is None:
        return ""
    if isinstance(value, dict):
        return f"<{value.get('bytes', '?')} bytes of binary data>" if value.get("type") == "blob" else ""
    text = _SPACE.sub(" ", _TAG.sub("", str(value))).strip()
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _pick(values, count=3):
    """The most informative 'Key: value' pairs from a row of named values."""
    chosen, used = [], set()
    lowered = {key: str(key).lower().strip() for key in values}
    ranked = [k for want in _PREFERRED for k in values if lowered[k] == want]
    ranked += [k for k in values if k not in ranked]
    for key in ranked:
        name = lowered[key]
        value = values[key]
        if key in used or value in (None, "", " ") or any(name == s or name.endswith(" " + s) for s in _SKIP):
            continue
        if any(word in name for word in ("time", "date")):
            continue
        text = _clean(value)
        if not text or text in ("0", "-1", "None", "null"):
            continue
        chosen.append(f"{key}: {text}")
        used.add(key)
        if len(chosen) == count:
            break
    return chosen


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sqlite_row(finding, detail):
    values = detail.get("values") or {}
    table = str(detail.get("table", ""))
    if table == "sms" and "body" in values:
        kind = _SMS_TYPE.get(_int(values.get("type")), "SMS")
        direction = "to" if kind in ("Sent", "Outbox", "Draft", "Failed", "Queued") else "from"
        return f"{kind} SMS {direction} {_clean(values.get('address'), 40) or 'unknown'}: “{_clean(values.get('body'), 140)}”"
    if table == "calls" and "number" in values:
        name = _clean(values.get("name"), 40)
        seconds = _int(values.get("duration"))
        return (f"{_CALL_TYPE.get(_int(values.get('type')), 'Call')} {'with' if _int(values.get('type')) != 2 else 'to'} "
                f"{_clean(values.get('number'), 30)}{' (' + name + ')' if name else ''}"
                f"{f', {seconds} s' if seconds else ''}")
    if table == "urls" and "url" in values:
        title = _clean(values.get("title"), 80)
        return f"Visited {title + ' — ' if title else ''}{_clean(values.get('url'), 120)}"
    database = PurePosixPath(finding.get("path", "")).name
    pairs = _pick(values)
    return f"{database} › {table}: " + (" · ".join(pairs) if pairs else "row")


def describe(finding):
    """One readable sentence for a finding, so investigators do not have to read raw JSON."""
    source, kind = finding.get("source", ""), finding.get("kind", "")
    detail = finding.get("detail") if isinstance(finding.get("detail"), dict) else {}
    path = finding.get("path", "")
    name = PurePosixPath(str(path).replace("\\", "/")).name or path
    text = None
    if source == "inventory":
        text = (f"Evidence file {path}, {detail.get('size', 0):,} bytes, "
                f"SHA-256 {str(detail.get('sha256', ''))[:16]}…")
    elif kind == "analysis_error":
        text = f"Could not read {name}{' table ' + str(detail['table']) if detail.get('table') else ''}: {_clean(detail.get('error'), 120)}"
    elif kind == "analysis_warning":
        text = f"{name}: {_clean(detail.get('warning'), 140)}"
    elif source == "aleapp":
        pairs = _pick(detail)
        text = f"{_report_name(finding).strip()}: " + (" · ".join(pairs) if pairs else "record")
    elif source == "sqlite" and kind == "database_row":
        text = _sqlite_row(finding, detail)
    elif source == "sqlite" and kind == "database_table":
        rows = detail.get("rows")
        size = f"{rows:,} rows" if isinstance(rows, int) else f"more than {detail.get('rows_exported', 0):,} rows (cut at the row limit)"
        text = f"Database table {detail.get('table')} in {name}: {size}"
    elif source == "exiftool":
        parts = [f"{detail.get('File:FileType') or 'File'} {name}"]
        taken = detail.get("EXIF:DateTimeOriginal") or detail.get("QuickTime:CreateDate")
        camera = " ".join(str(detail[k]) for k in ("EXIF:Make", "EXIF:Model") if detail.get(k))
        if taken:
            parts.append(f"taken {taken}")
        if camera:
            parts.append(f"camera {camera}")
        if detail.get("Composite:GPSPosition"):
            parts.append(f"GPS {detail['Composite:GPSPosition']}")
        if detail.get("Composite:ImageSize"):
            parts.append(f"{str(detail['Composite:ImageSize']).replace(' ', '×')} px")
        if "ExifTool:Error" in detail or "Error" in detail:
            parts.append("could not be read: " + _clean(detail.get("ExifTool:Error") or detail.get("Error"), 80))
        text = ", ".join(parts)
    elif source == "sleuthkit" and kind == "filesystem_entry":
        directory = str(detail.get("mode", "")).startswith("d")
        size = "" if directory else ", {:,} bytes".format(detail.get("size") or 0)
        text = f"{'Deleted ' if detail.get('deleted') else ''}{'folder' if directory else 'file'} {path}{size}"
        text = text[:1].upper() + text[1:]
    elif source == "sleuthkit" and kind == "file_time":
        flags = [word for flag, word in _MACB.items() if flag in str(detail.get("macb", ""))]
        text = f"{'Deleted file' if detail.get('deleted') else 'File'} {', '.join(flags) or 'time'}: {path}"
    elif kind == "timestamp_anomaly":
        text = (f"Created time looks earlier than expected (possible timestamp change, check it): {path}")
    elif source == "plaso":
        label = detail.get("timestamp_desc")
        message = _clean(detail.get("message"), 170)
        text = f"{label + ': ' if label and label != 'Not a time' else ''}{message or detail.get('data_type', '')}"
    elif kind == "rule_match":
        description = (detail.get("metadata") or {}).get("description")
        text = f"YARA rule {detail.get('rule')} matched {name}{' (' + _clean(description, 80) + ')' if description else ''}"
    elif source == "mvt" and kind == "indicator":
        text = f"MVT {str(detail.get('level', 'alert')).lower()}: {_clean(detail.get('message'), 170)}"
    elif source == "mvt" and "body" in detail:
        text = f"SMS {_clean(detail.get('address'), 40)}: “{_clean(detail.get('body'), 140)}”"
    if not text:
        pairs = _pick(detail.get("values") if isinstance(detail.get("values"), dict) else detail)
        text = f"{name}: " + (" · ".join(pairs) if pairs else _clean(json.dumps(detail, ensure_ascii=False), 120))
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT - 1] + "…"


def enrich(result):
    """A copy of a case result with the overview and, on every finding, its category, label and text.

    Used for display only (HTML report and dashboard); results.json on disk is never changed.
    """
    def decorate(item):
        key = categorize(item)
        return {**item, "category": key, "category_label": LABELS[key], "text": describe(item)}

    return {**result, "overview": case_overview(result), "categories": [list(c) for c in CATEGORIES],
            "findings": [decorate(f) for f in result.get("findings") or []],
            "timeline": [decorate(f) for f in result.get("timeline") or []]}
