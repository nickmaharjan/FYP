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

## Expected-findings evaluation

Added November 2026 (verification and evaluation stream). `mobile_df.evaluation` compares a finished case with the fixture's `expected.json`, turning the demo's expected values into repeatable checks:

| Expectation | Check | Depends on |
|---|---|---|
| (always) | Original evidence integrity is `verified` | pipeline |
| `sqlite_database_files` | Distinct SQLite databases discovered | sqlite |
| `sqlite_sms_rows` | Rows exported from the `sms` table | sqlite |
| `mvt_sms_rows` | Records in MVT's `sms` output | mvt |
| `yara_rule` | Named rule matched at least once | yara |
| `media_files` | Files with ExifTool metadata | exiftool |
| `image_file` | File listed from a filesystem image (image cases only) | sleuthkit |
| `shared_url` | URL correlated across at least two tools | two of sqlite, aleapp, mvt |

A check whose tool was not selected, unavailable or not applicable is `skipped` with the reason rather than counted as a pass or failure. Unknown expectation keys are reported as `unsupported`. The verdict is `fail` if any check fails, `pass` if at least one fixture check passes, and otherwise `inconclusive`. `score` is passes divided by scored checks.

Verified on macOS with Python 3.14 (SQLite and ExifTool only available): the demo scored `pass` with 4 passes and 4 explicit skips. The MVT check relies on MVT naming its SMS output `sms.json`; it is covered by a synthetic unit test and still needs confirmation on the Windows workspace with the real MVT runtime. This is a regression check on controlled fixtures, not an accuracy measure for real evidence.

## Repeated controlled benchmark (18 November 2026)

`python -m mobile_df.benchmark --runs 3` on Windows 11 x64, Python 3.12.14, with SQLite 3.53.1, yara-python 4.5.4, ExifTool 13.59, ALEAPP 2026.4.1, MVT 2026.9.7 and The Sleuth Kit 4.15.0 installed (Plaso not installed):

| Case | Verdicts | Check pass rate | Wall time mean (min-max) s | Findings | Timeline events | Same findings every run |
|---|---|---|---|---|---|---|
| Extraction (5 tools) | pass, pass, pass | 100% (7/7 scored checks per run) | 18.8 (14.6-27.3) | 26 | 11 | yes |
| FAT12 image (Sleuth Kit + YARA) | pass, pass, pass | 100% (4/4) | 0.74 (0.68-0.78) | 8 | 1 | yes |

Mean per-tool time in the extraction case: ALEAPP 11.2 s, MVT 6.3 s, ExifTool 0.45 s, YARA 0.38 s, SQLite 0.28 s. ALEAPP dominates run time and its variance explains the wide wall-time range. The image check `image_file_time` confirms NOTE.TXT's modification date (2026-09-20) reaches the timeline.

## NIST NTFS E01 test image

`ntfs1-gen1.E01` (NIST CFReDS NTFS test image, 9.3 MB, single segment) with The Sleuth Kit, ExifTool and SQLite:

| Measure | Before this milestone | After |
|---|---|---|
| Sleuth Kit findings | 35 file names | 39 entries with times, plus 55 timeline events |
| Timeline events | 0 | 55 (original 2008-2009 NTFS times) |
| ExifTool status | `failed` (exit 1) | `partial`: could not read 4 of 12 files (the NTFS-encrypted copies) |
| Evidence integrity | verified | verified |

The 4 files in `Encrypted/` are EFS-encrypted; the project does not decrypt them, which is expected. Their `RAW/` and `Compressed/` copies were read correctly.

## Remaining evaluation

Plaso needs a real compatible runtime and dataset. MVT bugreport/AndroidQF modes need their own fixtures. Real acquired Android images, additional application schemas, larger datasets, encrypted inputs and manual-versus-automated coverage comparisons remain necessary for the proposal's final academic evaluation. Raw image recovery was verified using FAT12, not Android ext4/F2FS. No forensic accuracy or speedup claim is made beyond these tests.
