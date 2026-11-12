# Prototype evaluation

Tested on Windows x64 with Python 3.12.14 on 2026-09-20. These results describe small controlled fixtures, not accuracy across all Android versions, applications or real-world forensic images.

## Automated checks

`python -m unittest discover -s tests -v`: **15 tests passed**, including the installed-tool integration test. The suite completed in approximately 12 seconds on this machine.

Coverage includes SQLite tables and row content, databases without file extensions, uncheckpointed WAL data, SHA-256 evidence preservation, deliberate source modification detection, ZIP extraction, path traversal and case-insensitive duplicate rejection, archive size limits, protection of existing cases, subprocess failure isolation, timeouts, cancellation, bounded row export, UTC conversion, exact-value correlations, report script escaping, API token requirements and Origin checks.

The Plaso test uses representative command/output fixtures. It verifies two-stage orchestration and JSON-line normalization, not the real Plaso parser stack.

## Actual tool executions

| Fixture | Result |
|---|---|
| SQLite SMS and Chrome databases | 10 normalized findings, including table summaries and rows |
| YARA benign marker | 2 matches in the extraction; match offsets retained |
| ExifTool synthetic PNG | 1 metadata artifact |
| ALEAPP Android-shaped extraction | 5 TSV artifacts from SMS/backup/browser parsers |
| MVT synthetic SMS backup and STIX2 indicator | 3 normalized records: SMS, URL and indicator alert; duplicate alert export excluded |
| Sleuth Kit synthetic FAT12 image | Recursive listing and allocated NOTE.TXT recovery succeeded; YARA found the marker in the recovered file |

The extraction dashboard run produced **26 findings, 11 timestamped events, and 6 cross-source links** in approximately **7.7 seconds**. Original evidence integrity verified. Its overall status is `completed_with_warnings` because Plaso was selected but unavailable; Sleuth Kit correctly reported `not_applicable` for a directory. The dedicated image case completed successfully.

Tool versions: yara-python 4.5.4, ExifTool 13.59, ALEAPP v2026.4.1, MVT 2026.9.7, The Sleuth Kit 4.15.0. SQLite is Python's bundled library; its version is recorded by `doctor` and in each case. Executed binary SHA-256 hashes and command arguments are recorded in case results. Portable download versions and archive checksums are pinned in `scripts/setup.ps1`.

## Browser workflow

Verified the local dashboard by starting a synthetic case through its UI, observing completion, viewing the per-tool results, and searching for the synthetic domain. Searching returned 11 supporting records from SQLite, ALEAPP and MVT. The layout was visually inspected in the in-app browser.

## Desktop conversion status

The initial desktop conversion is now present as a Tkinter workbench that reuses the existing pipeline. Its source provides recent-case navigation, tool readiness, evidence selection, threaded analysis, and local report handoff. The graphite/lime desktop and browser styling follows the project's non-generic UI requirements. The desktop package still needs interactive Windows review, installation/update flows, and a signed or otherwise distribution-ready installer before it should be treated as a distributable app.

## Remaining evaluation

Plaso needs a real compatible runtime and dataset. MVT bugreport/AndroidQF modes need their own fixtures. Real acquired Android images, additional application schemas, larger datasets, encrypted inputs and manual-versus-automated coverage comparisons remain necessary for the proposal's final academic evaluation. Raw image recovery was verified using FAT12, not Android ext4/F2FS. No forensic accuracy or speedup claim is made beyond these tests.
