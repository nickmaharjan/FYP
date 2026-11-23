# Prototype evaluation

Tested on Windows x64 with Python 3.12.14 on 2026-09-20. These results describe small controlled fixtures, not accuracy across all Android versions, applications or real-world forensic images.

## Automated checks

`python -m unittest discover -s tests -v`: **15 tests passed** at that date, including the installed-tool integration test. The suite completed in approximately 12 seconds on this machine.

On 2026-11-20 the suite on `master` has **67 tests**: all pass on macOS with Python 3.14, with the 2 installed-tool tests skipped because the full tool set is not installed there.

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
| `parameters` | Case was analysed with the options the fixture was built for (e.g. `max_rows`) | pipeline |
| `tool_status` | Each listed tool ended with the expected run status (e.g. `partial`) | pipeline |
| `sqlite_table_rows` | Exact row count for each `path::table` | sqlite |
| `sqlite_truncated_tables` | Exactly these `path::table` entries were cut off at the row limit | sqlite |
| `sqlite_row_values` | Rows with these column values were exported (Unicode, WAL-only rows, odd table names) | sqlite |

A check whose tool was not selected, unavailable or not applicable is `skipped` with the reason rather than counted as a pass or failure. Unknown expectation keys are reported as `unsupported`. The verdict is `fail` if any check fails, `pass` if at least one fixture check passes, and otherwise `inconclusive`. `score` is passes divided by scored checks.

Verified on macOS with Python 3.14 (SQLite and ExifTool only available): the demo scored `pass` with 4 passes and 4 explicit skips. The MVT check relies on MVT naming its SMS output `sms.json`; it is covered by a synthetic unit test and still needs confirmation on the Windows workspace with the real MVT runtime. This is a regression check on controlled fixtures, not an accuracy measure for real evidence.

## Larger SQLite fixture (20 November 2026)

`python -m mobile_df.sqlite_fixture OUTPUT [--max-rows 100]` generates six Android-shaped app databases (WhatsApp-style messages, contacts, call log, Gmail-style mail with BLOBs, Chrome `History` without an extension, Telegram-style cache with rows only in the uncheckpointed `-wal` file), plus a text file and an empty file named `.db`. It then analyses them with SQLite and scores the case against the generated `expected.json`.

Verified on macOS, Python 3.14, at `max_rows` 50, 60 and 100: verdict `pass` with 7/7 checks. All of the following were confirmed:
- exact row counts for 7 tables, including an empty table and a table named `weird "quoted" table`;
- the 3 tables larger than the limit are the only ones marked truncated, and the SQLite run is `partial`;
- the 3 WAL-only rows are exported (the main file alone holds 0 rows);
- a Unicode caller name survives unchanged;
- the two non-databases are ignored without an error.

Analysing the same fixture with a different row limit is reported as `fail` on `parameters`, `tool_status` and `sqlite_truncated_tables`, not silently passed. Not yet run on the Windows E1 workspace.

## Repeated controlled benchmark (18 November 2026)

`python -m mobile_df.benchmark --runs 3` on Windows 11 x64, Python 3.12.14, with SQLite 3.53.1, yara-python 4.5.4, ExifTool 13.59, ALEAPP 2026.4.1, MVT 2026.9.7 and The Sleuth Kit 4.15.0 installed (Plaso not installed):

| Case | Verdicts | Check pass rate | Wall time mean (min-max) s | Findings | Timeline events | Same findings every run |
|---|---|---|---|---|---|---|
| Extraction (5 tools) | pass, pass, pass | 100% (7/7 scored checks per run) | 18.8 (14.6-27.3) | 26 | 11 | yes |
| FAT12 image (Sleuth Kit + YARA) | pass, pass, pass | 100% (4/4) | 0.74 (0.68-0.78) | 8 | 1 | yes |

Mean per-tool time in the extraction case: ALEAPP 11.2 s, MVT 6.3 s, ExifTool 0.45 s, YARA 0.38 s, SQLite 0.28 s. ALEAPP dominates run time and its variance explains the wide wall-time range. The image check `image_file_time` confirms NOTE.TXT's modification date (2026-09-20) reaches the timeline.

## Four-case controlled benchmark (18 November 2026, second run)

Two more evidence types were added to the controlled fixtures: the extraction as a ZIP export (unpacked into the case before analysis) and an unencrypted Android `.ab` backup of the SMS app (checked by MVT). `python -m mobile_df.benchmark --runs 3`, same machine and tools as above:

| Case | Verdicts | Check pass rate | Wall time mean (min-max) s | Findings | Timeline events | Same findings every run |
|---|---|---|---|---|---|---|
| Extraction folder (5 tools) | pass x3 | 100% | 15.3 (14.9-15.5) | 26 | 11 | yes |
| ZIP export (5 tools) | pass x3 | 100% | 15.2 (14.8-15.5) | 22 | 11 | yes |
| Android `.ab` backup (MVT) | pass x3 | 100% | 1.9 (1.8-1.9) | 4 | 3 | yes |
| FAT12 image (Sleuth Kit + YARA) | pass x3 | 100% | 0.66 (0.53-0.77) | 8 | 1 | yes |

The ZIP case has 4 fewer findings than the folder only because the inventory lists one evidence file (the ZIP) instead of five; tool findings are identical. YARA is not scored on the backup: the backup is compressed, so the marker cannot match (see [tool support](tool-support.md#known-limitation-compressed-containers-and-yara)); running it gives `fail` for `yara_rule`, which is the correct observation.

## NIST NTFS E01 test image

`ntfs1-gen1.E01` (NIST CFReDS NTFS test image, 9.3 MB, single segment) with The Sleuth Kit, ExifTool and SQLite:

| Measure | Before this milestone | After |
|---|---|---|
| Sleuth Kit findings | 35 file names | 39 entries with times, plus 55 timeline events |
| Timeline events | 0 | 55 (original 2008-2009 NTFS times) |
| ExifTool status | `failed` (exit 1) | `partial`: could not read 4 of 12 files (the NTFS-encrypted copies) |
| Evidence integrity | verified | verified |

The 4 files in `Encrypted/` are EFS-encrypted; the project does not decrypt them, which is expected. Their `RAW/` and `Compressed/` copies were read correctly.

## NPS 2008 "Jean" disk image (incomplete segment set)

`nps-2008-jean.E01` (Windows XP laptop, 10 GiB disk, NTFS partition at sector 63; 1.5 GB first segment only) analysed with `--image-offset 63`. The filesystem header is readable, but the root directory index lies about 7.2 GB into the disk, beyond the first segment, so `fls` fails. The `.E01` ends with a `next` section, confirming that `nps-2008-jean.E02` is needed.

| Measure | Before split-image support | After |
|---|---|---|
| Sleuth Kit status | `failed`: "Tool did not complete successfully; inspect logs" | `failed`: "Image segment set is incomplete: nps-2008-jean.E01 says more data follows but nps-2008-jean.E02 is missing" |
| Case warning | none | the same message |
| Evidence integrity | verified | verified |

With both segments present, the pipeline now copies and verifies both; this has been verified with a raw split FAT12 image read by the real Sleuth Kit and with the complete `nps-2008-jean` set (next section).

## NPS 2008 "Jean" disk image, complete set (22 November 2026)

Both segments, from [Digital Corpora](https://digitalcorpora.org/corpora/disk-images/) (`corpora/drives/nps-2008-m57-jean/`): `nps-2008-jean.E01` (1,572,860,321 bytes, ends with a `next` section) and `nps-2008-jean.E02` (1,466,890,611 bytes, ends with `done`). The Sleuth Kit opens them as one 10 GiB disk (EWF image, stored MD5 `78a52b5bac78f4e711607707ac0e3f93`). `cli analyze nps-2008-jean.E01 --image-offset 63 --timeout 1800`, same tools as the benchmark (Plaso and YARA rules not used), took 8 min 9 s:

| Measure | `.E01` only (19 Nov) | `.E01` + `.E02` |
|---|---|---|
| Segments found, hashed, copied and re-verified | 1 | 2 (`parameters.image_segments`) |
| Sleuth Kit | `failed`: `.E02` is missing | `partial`: 50,000-finding cap reached |
| Files recovered by `tsk_recover` | 0 | 30,722 |
| Timeline events | 0 | 29,513 (1996 to 21 July 2008) |
| Findings | 2 | 56,463 (also SQLite 3,788, ExifTool 2,657) |
| Evidence integrity | verified | verified |

The scenario's key file is found and recovered: `Documents and Settings/Jean/Desktop/m57biz.xls` (291,840 bytes, modified 2008-07-20 01:28:03 UTC), with Windows and Office *Recent* shortcuts (`m57biz.lnk`, `m57biz.LNK`) created or modified at 01:27:42 to 01:28:04 UTC, showing the file was opened at that time. The 4,756 `timestamp_anomaly` leads (standard-information creation earlier than file-name creation) are review leads only: on Windows XP many come from software installation and file copies.

## First real Plaso run (22 November 2026)

Plaso 20240308 through Docker (`plaso_docker_image: log2timeline/plaso:20240308`, 598 MB image) on the complete jean set, `--tools plaso --image-offset 63 --timeout 7200`. Both segments were visible in the container because the working folder is mounted read-only; the container had no network.

| Measure | Result |
|---|---|
| `log2timeline` (extraction) | `success` in 2,487 s; storage file 996 MB |
| `psort` (export to JSON lines) | `success` in 466 s; 1,773,196 events (3.0 GB) |
| Run status | `partial`: only the first 50,000 events reached the case |
| Evidence integrity | verified |

Most frequent event types among the 50,000 loaded: `fs:stat` 27,385, `pe_coff:file` 15,156, `windows:registry:appcompatcache` 3,491, `msiecf:url` 1,439, `windows:registry:userassist` 474, `windows:lnk:link` 315.

Two findings for the design:
- `psort` output is not in time order, so the 50,000 loaded events stop in April 2008 and miss the July 2008 activity of the scenario. A per-tool cap is unsuitable for Plaso: whole-disk timelines need date and event-type filtering instead.
- Many early timestamps (1993-1994) are dates written into files by their makers (Office templates, program compile times), not user activity. The new case summary keeps these under *Files & system* and only counts records such as shortcuts, *UserAssist* and browser history as user activity.

## Public Android 9 reference image (Google Pixel 3, 21 November 2026)

First run on a real Android device extraction. The dataset is the public Android 9 reference image created by Joshua Hickman and published on [Digital Corpora](https://digitalcorpora.org/corpora/cell-phones/). It is a test phone filled with app data for research and training; it contains no real person's data. Provenance:

- Downloaded `android_9.tar.gz` (4,479,032,673 bytes). It matched the server's S3 multipart ETag `87c3ce2e43487150502972bf2c3d5a38-534`; SHA-256 `efee950cda419a68cdebfb28a264c85783d1a5e44038334d7773711d97ef464f`.
- The inner `Google Pixel 3.tar` (the `/data` partition; 28,977 files, 7.4 GB, 375 `.db`/`.sqlite` files, no links) matched the author's published MD5 `c9cb1909efd9a5aca2316103dba08037` and SHA-1 `c19ec5970e200007e4b921dc49d1f70a13ff902c`.
- The image is not committed to the repository.

`cli analyze "Google Pixel 3.tar" --timeout 1800` on the Windows workspace (same tool versions as the benchmark, Plaso not installed, no YARA rules) took 10 min 42 s:

| Tool | Status | Notes |
|---|---|---|
| ALEAPP 2026.4.1 | `partial` | 162 reports, about 65,700 rows, in 171 s. The 50,000-finding cap was reached; the full output stays in `tools/aleapp`. One report (Netstats) alone produced 21,134 rows. |
| SQLite 3.53.1 | `failed` before the fix below | 346 databases reached the case in 238 s before the 50,000-finding cap |
| ExifTool 13.59 | `partial` | 1,223 media files; 7 encrypted Silent Phone files unreadable |
| The Sleuth Kit, MVT | `not_applicable` | A file-system TAR is neither a disk image nor a backup |

The case had 101,224 findings, 11,738 timeline events and 554 correlations, and evidence integrity was verified.

**SMS compared with the author's answer sheet.** The image comes with `SMS Messages.xlsx`, listing 75 SMS messages found by a commercial tool, with the source of each. The project's results compare as follows:

| Source in the answer sheet | Sheet | This project |
|---|---|---|
| `com.android.providers.telephony/databases/mmssms.db`, table `sms` | 30 records | 29 rows exported by SQLite. The extra sheet record is probably recovered from deleted space, which these tools do not carve. |
| `com.google.android.gms/databases/icing_mmssms.db-wal` | 29 records | The `mmssms` table was exported (176 rows, including the WAL) |
| `com.google.android.apps.messaging/databases/bugle_db` (+`-wal`) | 12 records | `messages` (184 rows) and `parts` (182 rows) were exported |
| ALEAPP SMS reports | — | `SMS Messages` 49 rows, `SMS and MMS Messages` 202 rows |

This is a coverage check, not an accuracy score: the sheet counts carved and deduplicated records differently from a row export.

**Defect found and fixed.** Chrome's `History`, `Web Data` and `OfflinePages.db` store protobuf bytes in `TEXT` columns. SQLite's text decoding raised an error, the worker abandoned the rest of each database (in `History`, every table after `meta`, including `urls` and `visits`), and the whole SQLite run was marked `failed`. Now:
- text that is not valid UTF-8 is kept as a blob value;
- one unreadable table no longer stops the rest of its database;
- the run is `partial` with a named reason when some databases or tables cannot be read, and `failed` only when none can.

The fixed worker, run on the same extracted copy, gives:

| Measure | Before | After |
|---|---|---|
| Databases opened | 576 | 576, none unreadable |
| Errors | 4 (three Chrome databases and LINE `search.sqlite`) | 1 table (LINE full-text index `idxt`, which needs an SQLite module that is not available) |
| Tables / rows exported | 3,761 / 79,766 | 3,794 / 79,830 |
| Chrome `History` | stopped at `meta` | `urls` 14, `visits` 22, `keyword_search_terms` 5 |

Tests: `tests/test_sqlite_robustness.py`.

Still open from this run: the per-tool 50,000-finding cap is too low for a whole phone. ALEAPP lost about 15,500 rows from the case view (they remain in its raw output), and SQLite rows beyond the cap are only in the raw log. A per-report cap or a higher limit is needed.

## Remaining evaluation

Plaso has now run for real through Docker (above), but its whole-disk timeline exceeds the finding cap. MVT bugreport/AndroidQF modes need their own fixtures. One public Android 9 extraction has now been analysed (above); more Android versions, additional application schemas, larger datasets, encrypted inputs and manual-versus-automated coverage comparisons remain necessary for the proposal's final academic evaluation. Raw image recovery was verified using FAT12, not Android ext4/F2FS. No forensic accuracy or speedup claim is made beyond these tests.
