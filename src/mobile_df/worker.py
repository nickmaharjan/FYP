"""Isolated SQLite and YARA workers. A bad database cannot stall the UI."""
import argparse
import base64
import json
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path

from .core import artifact, timestamp_from
from .evidence import files_under


def emit(value):
    print(json.dumps(value, ensure_ascii=False), flush=True)


def json_value(value):
    if isinstance(value, bytes):
        return {"type": "blob", "bytes": len(value), "base64_preview": base64.b64encode(value[:64]).decode()}
    if isinstance(value, str) and len(value) > 8192:
        return value[:8192] + " [TRUNCATED at 8192 characters]"
    return value


def text_or_bytes(value):
    """Decode a TEXT value; keep it as bytes when it is not valid UTF-8.

    Apps such as Chrome store protobuf and other binary data in TEXT columns. SQLite's default
    decoding raises on those, which used to abandon the whole database.
    """
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return bytes(value)


def sqlite_scan(root, max_rows):
    databases, unreadable, table_errors = 0, [], 0
    for path in files_under(root):
        with path.open("rb") as stream:
            if stream.read(16) != b"SQLite format 3\x00":
                continue
        relative = path.relative_to(root).as_posix()
        databases += 1
        try:
            # Working copies include -wal and -shm companions. Do not use immutable=1:
            # it can silently ignore uncheckpointed WAL records.
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("PRAGMA trusted_schema=OFF")
                db.text_factory = text_or_bytes
                deadline = time.monotonic() + 30
                db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
                tables = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
                for (table,) in tables[:200]:
                    quoted = '"' + table.replace('"', '""') + '"'
                    try:
                        cursor = db.execute(f"SELECT * FROM {quoted} LIMIT ?", (max_rows + 1,))
                        columns = [item[0] for item in cursor.description]
                        rows = cursor.fetchall()
                    except sqlite3.Error as exc:
                        # One unreadable table (corrupt page, missing module, time limit) must not hide the others.
                        table_errors += 1
                        emit(artifact("sqlite", "analysis_error", relative, {"table": table, "error": str(exc)},
                                      severity="warning", provenance={"table": table}))
                        continue
                    truncated = len(rows) > max_rows
                    emit(artifact("sqlite", "database_table", relative,
                                  {"table": table, "rows_exported": min(len(rows), max_rows),
                                   "rows": len(rows) if not truncated else None, "truncated": truncated,
                                   "columns": columns}, provenance={"table": table}))
                    for index, row in enumerate(rows[:max_rows]):
                        values = {key: json_value(value) for key, value in zip(columns, row)}
                        stamp, basis = timestamp_from(values)
                        emit(artifact("sqlite", "database_row", relative, {"table": table, "values": values},
                                      stamp, basis, provenance={"table": table, "result_row": index + 1}))
                if len(tables) > 200:
                    emit(artifact("sqlite", "analysis_warning", relative, {"warning": "Only the first 200 tables were analyzed"}))
        except sqlite3.Error as exc:
            unreadable.append(relative)
            emit(artifact("sqlite", "analysis_error", relative, {"error": str(exc)}, severity="warning"))
    # A one-line summary on stderr lets the adapter report a partial result instead of a failure.
    print(json.dumps({"databases": databases, "unreadable_databases": len(unreadable),
                      "unreadable_tables": table_errors, "examples": unreadable[:3]}), file=sys.stderr)
    return 1 if unreadable or table_errors else 0


def yara_scan(root, rules):
    import yara
    compiled = yara.compile(filepath=str(rules))
    errors = 0
    for path in files_under(root):
        relative = path.relative_to(root if root.is_dir() else root.parent).as_posix()
        try:
            for match in compiled.match(str(path), timeout=30):
                matches = []
                for string in match.strings:
                    for instance in string.instances[:20]:
                        matches.append({"identifier": string.identifier, "offset": instance.offset,
                                        "length": instance.matched_length})
                emit(artifact("yara", "rule_match", relative,
                              {"rule": match.rule, "namespace": match.namespace, "tags": match.tags,
                               "metadata": match.meta, "matches": matches}, severity="warning",
                              provenance={"rule": match.rule}))
        except yara.Error as exc:
            errors += 1
            emit(artifact("yara", "analysis_error", relative, {"error": str(exc)}, severity="warning"))
    return 1 if errors else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", choices=["sqlite", "yara"])
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--max-rows", type=int, default=1000)
    args = parser.parse_args()
    return sqlite_scan(args.evidence, args.max_rows) if args.tool == "sqlite" else yara_scan(args.evidence, args.rules)


if __name__ == "__main__":
    raise SystemExit(main())
