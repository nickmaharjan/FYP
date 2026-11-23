"""Plain-language case overview: findings grouped by what they are, and tool outcomes in plain words.

An investigator thinks "show me the messages", not "show me SQLite rows". This module maps every
finding to one category (Messages, Calls, Contacts, ...) using only what the finding already
records (its tool, kind, path, ALEAPP report name, ExifTool file type or Plaso data type), and
builds the summary shown before any table. It is GUI-free so the desktop app, the HTML report and
tests can share it.
"""
import collections
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
