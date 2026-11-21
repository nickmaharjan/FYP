"""Larger synthetic SQLite fixture with known expected findings (test plan section 5).

Builds several Android-shaped app databases whose exact contents are known, so the SQLite
adapter can be scored on row counts, row-limit truncation, uncheckpointed WAL data, awkward
table names, Unicode and non-database files. Everything is generated; no real data is used.

    python -m mobile_df.sqlite_fixture OUTPUT [--max-rows 100]

creates OUTPUT/fixture (evidence + expected.json), analyses it with SQLite into OUTPUT/case,
and scores the case with ``mobile_df.evaluation``.
"""
import argparse
import json
import shutil
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from .core import write_json

BASE_MS = 1789905600000          # 2026-09-20T12:00:00Z, same anchor as the demo fixture
UNICODE_NAME = "Zoë Ŋ राम ✓"     # Latin accents, Latin Extended, Devanagari and a symbol
ODD_TABLE = 'weird "quoted" table'


def _db(path, statements, rows=()):
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db:
        for statement in statements:
            db.execute(statement)
        for sql, values in rows:
            db.executemany(sql, values)
        db.commit()


def create_sqlite_fixture(root, max_rows=100):
    """Create the fixture under ``root`` and return its paths and the options it expects."""
    if max_rows < 50:
        raise ValueError("max_rows must be at least 50 so the small tables (up to 40 rows) stay below the limit")
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=False)
    evidence = root / "evidence"
    data = evidence / "data/data"
    large, history = max_rows + 150, max_rows + 50

    msgstore = "data/data/com.whatsapp/databases/msgstore.db"
    _db(evidence / msgstore,
        ["CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER, "
         "timestamp INTEGER, text_data TEXT)"],
        [("INSERT INTO message VALUES (?,?,?,?,?)",
          [(i, i % 7, i % 2, BASE_MS + i * 60000, f"Synthetic message {i}") for i in range(1, large + 1)])])

    contacts = "data/data/com.android.providers.contacts/databases/contacts2.db"
    _db(evidence / contacts,
        ["CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, display_name TEXT)",
         "CREATE TABLE data (_id INTEGER PRIMARY KEY, raw_contact_id INTEGER, mimetype TEXT, data1 TEXT)"],
        [("INSERT INTO raw_contacts VALUES (?,?)", [(i, f"Synthetic contact {i}") for i in range(1, 21)]),
         ("INSERT INTO data VALUES (?,?,?,?)",
          [(i, (i + 1) // 2, "vnd.android.cursor.item/phone_v2", f"+1555010{i:04d}") for i in range(1, 41)])])

    calllog = "data/data/com.android.providers.contacts/databases/calllog.db"
    _db(evidence / calllog,
        ["CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, name TEXT, date INTEGER, duration INTEGER, type INTEGER)"],
        [("INSERT INTO calls VALUES (?,?,?,?,?,?)",
          [(i, f"+1555020{i:04d}", UNICODE_NAME if i == 1 else f"Caller {i}", BASE_MS + i * 3600000, i * 10, 1 + i % 3)
           for i in range(1, 31)])])

    mail = "data/data/com.google.android.gm/databases/mailstore.db"
    _db(evidence / mail,
        ["CREATE TABLE messages (_id INTEGER PRIMARY KEY, subject TEXT, attachment BLOB)",
         "CREATE TABLE drafts (_id INTEGER PRIMARY KEY, subject TEXT)",
         f'CREATE TABLE "{ODD_TABLE.replace(chr(34), chr(34) * 2)}" (v TEXT)'],
        [("INSERT INTO messages VALUES (?,?,?)", [(i, f"Synthetic subject {i}", bytes(range(i * 10))) for i in range(1, 6)]),
         (f'INSERT INTO "{ODD_TABLE.replace(chr(34), chr(34) * 2)}" VALUES (?)', [("odd-1",), ("odd-2",)])])

    # Chrome stores History without a file extension; detection must use the SQLite header.
    chrome = "data/data/com.android.chrome/app_chrome/Default/History"
    _db(evidence / chrome,
        ["CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_time INTEGER)",
         "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)"],
        [("INSERT INTO urls VALUES (?,?,?,?)",
          [(i, f"https://site{i}.example/page", f"Synthetic page {i}", 13434379200000000 + i) for i in range(1, history + 1)]),
         ("INSERT INTO visits VALUES (?,?,?)",
          [(i, i, 13434379200000000 + i) for i in range(1, history + 1)])])

    # A row that exists only in the write-ahead log: copy the database and its -wal while the
    # writer is still open, as an acquisition of a running phone would capture it.
    wal = "data/data/org.telegram.messenger/files/cache4.db"
    scratch = root / "wal-build"
    scratch.mkdir()
    with closing(sqlite3.connect(scratch / "cache4.db")) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA wal_autocheckpoint=0")
        db.execute("CREATE TABLE messages_v2 (mid INTEGER PRIMARY KEY, date INTEGER, message TEXT)")
        db.commit()
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")   # table definition in the main file
        db.executemany("INSERT INTO messages_v2 VALUES (?,?,?)",
                       [(1, 1789905600, "Synthetic WAL-only message"), (2, 1789905660, "Synthetic second WAL message"),
                        (3, 1789905720, "Synthetic third WAL message")])
        db.commit()                                       # rows only in cache4.db-wal
        (evidence / wal).parent.mkdir(parents=True)
        for suffix in ("", "-wal"):
            shutil.copy2(scratch / ("cache4.db" + suffix), evidence / (wal + suffix))
    shutil.rmtree(scratch)

    # Not databases: a .db text file and an empty .db file must be ignored, not reported.
    (data / "com.example.notes/databases").mkdir(parents=True)
    (data / "com.example.notes/databases/notes.db").write_text("plain text, not SQLite", encoding="utf-8")
    (data / "com.example.notes/databases/empty.db").write_bytes(b"")

    def key(path, table):
        return f"{path}::{table}"

    expected = {
        "description": f"Synthetic SQLite fixture for max_rows={max_rows}; never real data",
        "parameters": {"max_rows": max_rows},
        "tool_status": {"sqlite": "partial"},
        "sqlite_database_files": 6,
        "sqlite_table_rows": {
            key(contacts, "raw_contacts"): 20, key(contacts, "data"): 40, key(calllog, "calls"): 30,
            key(mail, "messages"): 5, key(mail, "drafts"): 0, key(mail, ODD_TABLE): 2, key(wal, "messages_v2"): 3},
        "sqlite_truncated_tables": sorted([key(msgstore, "message"), key(chrome, "urls"), key(chrome, "visits")]),
        "sqlite_row_values": [
            {"table": key(calllog, "calls"), "values": {"_id": 1, "name": UNICODE_NAME}},
            {"table": key(wal, "messages_v2"), "values": {"mid": 1, "message": "Synthetic WAL-only message"}},
            {"table": key(mail, ODD_TABLE), "values": {"v": "odd-2"}},
            {"table": key(msgstore, "message"), "values": {"_id": 1, "text_data": "Synthetic message 1"}}],
    }
    write_json(root / "expected.json", expected)
    return {"evidence": evidence, "expected": root / "expected.json", "options": {"max_rows": max_rows, "tools": ["sqlite"]}}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m mobile_df.sqlite_fixture", description=__doc__.splitlines()[0])
    parser.add_argument("output", type=Path, help="New folder for the fixture and its case")
    parser.add_argument("--max-rows", type=int, default=100)
    args = parser.parse_args(argv)
    from .evaluation import evaluate_case
    from .pipeline import analyze
    try:
        fixture = create_sqlite_fixture(args.output / "fixture", args.max_rows)
        analyze(fixture["evidence"], args.output / "case", "SQLITE-FIXTURE", config={}, **fixture["options"],
                progress=lambda message: print(message, file=sys.stderr, flush=True))
    except (OSError, ValueError) as exc:
        parser.exit(2, f"error: {exc}\n")
    evaluation = evaluate_case(args.output / "case", fixture["expected"])
    write_json(args.output / "case" / "evaluation.json", evaluation)
    print(json.dumps({"verdict": evaluation["verdict"], "summary": evaluation["summary"],
                      "evaluation": str((args.output / "case" / "evaluation.json").resolve())}, indent=2))
    return 0 if evaluation["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
