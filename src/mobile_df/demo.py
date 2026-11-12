"""Small, deterministic synthetic fixtures. Contains no personal or malicious data."""
import json
import sqlite3
import struct
import zlib
from contextlib import closing
from pathlib import Path

from .core import write_json


def create_demo(root):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=False)
    evidence = root / "evidence"
    sms_folder = evidence / "data/data/com.android.providers.telephony/databases"
    sms_folder.mkdir(parents=True)
    message = "Synthetic training message: https://training-ioc.example/check DFIR_DEMO_MARKER"
    with closing(sqlite3.connect(sms_folder / "mmssms.db")) as db:
        db.execute("CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, person INTEGER, date INTEGER, date_sent INTEGER, protocol INTEGER, read INTEGER, status INTEGER, type INTEGER, reply_path_present INTEGER, subject TEXT, body TEXT, service_center TEXT, locked INTEGER, sub_id INTEGER, error_code INTEGER, seen INTEGER)")
        db.execute("INSERT INTO sms VALUES (1,1,'+15550100001',NULL,1789905600000,0,0,1,-1,1,0,NULL,?,'+15550000000',0,1,0,1)", (message,))
        db.execute("CREATE TABLE threads (_id INTEGER PRIMARY KEY, date INTEGER, message_count INTEGER, recipient_ids TEXT, snippet TEXT, snippet_cs INTEGER, read INTEGER, archived INTEGER, type INTEGER, error INTEGER, has_attachment INTEGER)")
        db.execute("INSERT INTO threads VALUES (1,1789905600000,1,'1',?,0,1,0,0,0,0)", (message,))
        db.execute("CREATE TABLE canonical_addresses (_id INTEGER PRIMARY KEY,address TEXT)")
        db.execute("INSERT INTO canonical_addresses VALUES (1,'+15550100001')")
        db.commit()
    backup = evidence / "apps/com.android.providers.telephony/d_f"
    backup.mkdir(parents=True)
    (backup / "000000_sms_backup").write_bytes(zlib.compress(json.dumps([
        {"address": "+15550100001", "date": "1789905600000", "date_sent": "0", "body": message, "type": "1", "read": "1"}
    ]).encode()))
    chrome = evidence / "data/data/com.android.chrome/app_chrome/Default"
    chrome.mkdir(parents=True)
    with closing(sqlite3.connect(chrome / "History")) as db:
        db.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER)")
        db.execute("INSERT INTO urls VALUES (1,'https://training-ioc.example/check','Synthetic training page',1,0,13434379200000000,0)")
        db.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER,from_visit INTEGER,transition INTEGER,segment_id INTEGER,visit_duration INTEGER)")
        db.execute("INSERT INTO visits VALUES (1,1,13434379200000000,0,1,0,0)")
        db.commit()
    media = evidence / "media/0/DCIM"
    media.mkdir(parents=True)
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xffffffff)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">2I5B", 2, 2, 8, 2, 0, 0, 0))
    png += chunk(b"tEXt", b"Description\x00Synthetic DFIR demo photo")
    png += chunk(b"IDAT", zlib.compress(b"\x00\x08\x7e\x81\x08\x7e\x81" * 2)) + chunk(b"IEND", b"")
    (media / "training.png").write_bytes(png)
    (evidence / "training-note.txt").write_text(message, encoding="utf-8")
    rules = root / "demo.yar"
    rules.write_text('rule DFIR_Demo_Marker { meta: description = "Benign training marker; not malware" strings: $marker = "DFIR_DEMO_MARKER" condition: $marker }\n', encoding="utf-8")
    iocs = root / "demo-iocs.json"
    write_json(iocs, {"type": "bundle", "id": "bundle--89a1f8a1-c83c-4eda-a256-aea568955172", "objects": [
        {"type": "indicator", "spec_version": "2.1", "id": "indicator--95420f0e-0b4e-4d8a-a3f5-786fe89b04a9",
         "created": "2026-09-20T00:00:00Z", "modified": "2026-09-20T00:00:00Z", "valid_from": "2026-09-20T00:00:00Z",
         "name": "Synthetic training domain", "pattern_type": "stix", "pattern": "[domain-name:value = 'training-ioc.example']"}]})
    create_fat12(root / "training-fat12.img")
    write_json(root / "expected.json", {"description": "Synthetic training evidence, never a real compromise",
               "sqlite_sms_rows": 1, "mvt_sms_rows": 1, "yara_rule": "DFIR_Demo_Marker",
               "shared_url": "https://training-ioc.example/check", "media_files": 1,
               "image_file": "NOTE.TXT", "sqlite_database_files": 2})
    return {"evidence": evidence, "yara_rules": rules, "iocs": iocs}


def create_fat12(path):
    """A standard 1.44 MB FAT12 fixture with a single allocated NOTE.TXT."""
    data = bytearray(2880 * 512)
    data[:3] = b"\xeb\x3c\x90"
    data[3:11] = b"DFIRDEMO"
    struct.pack_into("<HBHBHHBHHHII", data, 11, 512, 1, 1, 2, 224, 2880, 0xf0, 9, 18, 2, 0, 0)
    data[38] = 0x29
    struct.pack_into("<I", data, 39, 0x12345678)
    data[43:54] = b"DFIR DEMO  "
    data[54:62] = b"FAT12   "
    data[510:512] = b"\x55\xaa"
    for sector in (1, 10):
        offset = sector * 512
        data[offset:offset + 5] = b"\xf0\xff\xff\xff\x0f"
    root = 19 * 512
    body = b"Synthetic forensic image. DFIR_DEMO_MARKER\r\n"
    data[root:root + 11] = b"NOTE    TXT"
    data[root + 11] = 0x20
    struct.pack_into("<HHHI", data, root + 22, 0, ((2026 - 1980) << 9) | (9 << 5) | 20, 2, len(body))
    data[33 * 512:33 * 512 + len(body)] = body
    path.write_bytes(data)
