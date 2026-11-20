# Test plan

Owner: Sachin Gautam (verification and evaluation stream). Status: draft for the November 2026 – January 2027 checkpoint in the [desktop roadmap](desktop-roadmap.md). Last reviewed against `master` on 2026-11-20 (after #9 and #11).

This plan says what is tested, how, on which machines, and what still has to be tested before the September 20, 2027 50% gate. It describes the current prototype; it is not an accuracy claim. Results are recorded in [evaluation.md](evaluation.md).

## 1. Objectives

1. Every change to `master` keeps the automated suite green on the team's Windows workspace.
2. Evidence is never modified: hashing, working copies and the before/after integrity check are tested on every input type the tool accepts.
3. Each forensic adapter has a controlled fixture with **known expected findings**, scored by `mobile_df.cli evaluate`, so a regression shows up as a failed check rather than a changed number nobody notices.
4. Missing tools, failures, timeouts, cancellation and limits stay visible to the investigator and are tested as such.
5. Desktop workflows that cannot be unit tested are covered by a repeatable manual checklist (section 6).

## 2. Scope

| In scope | Out of scope for this checkpoint |
|---|---|
| Analysis pipeline, adapters, evidence staging and integrity | Acquiring or unlocking phones (the product does not do this) |
| Case library, review filters, CSV export, archive/restore/delete | Real acquired device evidence (never used in tests; see CONTRIBUTING) |
| Settings, progress model, cancel, re-run of interrupted cases | Forensic accuracy on real Android versions (needs authorised datasets; section 8) |
| Case handoff export and verification | Packaged Windows installer (not built yet) |
| Fixture evaluation (`evaluate`) and repeated-run benchmark | Performance tuning (measured from Feb 2027, section 9) |
| Dashboard API access control and report escaping | |
| Tool registry, pack verification and in-app install/update/repair | |
| Split and segmented disk images (raw split, E01) | |

## 3. Test environments

| ID | Environment | Tools | Purpose |
|---|---|---|---|
| E1 | Team Windows x64 workspace, Python 3.12, after `scripts/setup.ps1` | All six verified tools | Reference environment; installed-tool integration test must run, not skip |
| E2 | Any machine with Python ≥ 3.10 and no setup (fresh clone) | SQLite only (plus whatever happens to be installed) | Proves the suite does not silently depend on optional tools |
| E3 | Windows offline install from an offline kit, following [installation.md](installation.md) section 4 (`setup.ps1 -Offline -PackDir <packs>`, or **Install from offline kit** in the app) | All six | Offline setup path; confirm with `python -m mobile_df.registry --verify` |
| E4 | Docker Desktop with the official Plaso image (`plaso_docker_image`, [installation.md](installation.md) section 4b) | Plaso | Real Plaso execution; so far covered by the contract test and a simulated Docker run |

Rule from E2: a test that needs an optional tool must either skip with a reason or assert the `unavailable` outcome. It must not fail. (#6 fixed one such case in `tests/test_resume.py`.)

## 4. Automated test inventory

67 tests in `tests/` on `master` (73 with #10), run with `.\scripts\test.ps1` (or `python -m unittest discover -s tests -v` with `PYTHONPATH=src`).

| Area | File | Tests | What is covered |
|---|---|---|---|
| Evidence safety | `test_workflow.py` (EvidenceTests) | 5 | ZIP traversal and case-insensitive duplicates rejected, archive size limit, SQLite without extension and uncheckpointed WAL, deliberate source modification detected, archive pipeline and refusal to overwrite a case |
| Orchestration | `test_workflow.py` (OrchestrationTests) | 6 | Failed tool isolated, timeout and cancel recorded, Plaso command/parse contract, row limit marks `partial`, exact-value correlation and timezone handling, report escapes evidence HTML |
| Dashboard | `test_workflow.py` (DashboardTests) | 1 | API needs the session token and rejects other origins |
| Installed tools | `test_workflow.py` (InstalledToolsTests) | 1 | Real SQLite, YARA, ExifTool, ALEAPP, MVT on the demo; Sleuth Kit + YARA on the FAT12 image. **Skips outside E1** |
| Pipeline basics | `test_pipeline.py` | 2 | Hashes and SQLite on an extraction, output inside evidence rejected |
| Case library | `test_case_library.py` | 5 | Finding and timeline filters, CSV formula neutralisation, incomplete and cancelled cases listed |
| Desktop logic | `test_desktop_workflow.py` | 9 | Settings round trip and validation, tool selection, progress model against real pipeline messages, archive/restore/delete boundaries |
| Re-run | `test_resume.py` | 2 | Interrupted case records options; re-run completes; refusals for moved evidence/rules and old cases |
| Handoff | `test_handoff.py` | 5 | Package contents and exclusions, opt-in tool output, tamper detection, refusals, command line |
| Fixture evaluation | `test_evaluation.py` | 7 | Every expectation type, skip-not-fail for missing tools, integrity failure, unsupported keys, real SQLite demo run and `evaluate` CLI |
| Integrations | `test_integrations.py` | 9 | Sleuth Kit body-file parsing (times, file-name attribute, deleted entries, pipes), ExifTool per-file errors as `partial`, tool registry and pack verification, `image_file_time` check, log viewer reads case logs only, benchmark, desktop tool screen and log viewer render smoke test |
| Installer and Plaso | `test_installer_plaso.py` | 10 | Install from kit and download path with checksum verification, mismatch installs nothing, refusals, failed swap and cancel keep the previous install, Plaso Docker runs read-only without network and maps paths, ZIP export and `.ab` backup fixtures, setup checklist |
| Segmented images | `test_segments.py` | 5 | E01 and raw split sequences (complete, incomplete, wrong start), every segment hashed/copied/verified, real Sleuth Kit on raw split, missing segment named as the reason |

## 5. Controlled fixtures and expected findings

Fixtures are synthetic, generated by code, and contain no personal or malicious data. Expected values live next to the fixture and are scored with `evaluate`.

| Fixture | Status | Expected findings | Scored by |
|---|---|---|---|
| Demo extraction (`demo.py`): SMS DB, SMS backup, Chrome history, PNG, YARA marker, STIX2 indicator | Exists | `expected.json`: 2 SQLite DBs, 1 SMS row (SQLite), 1 SMS record (MVT), YARA rule `DFIR_Demo_Marker`, 1 media file, shared URL across tools | `cli demo` writes `case/evaluation.json` |
| ZIP export of the demo extraction | Exists (#9) | Same tool findings as the folder; inventory lists the ZIP | `mobile_df.benchmark` |
| Unencrypted Android `.ab` backup of the SMS app | Exists (#9) | MVT SMS records; YARA deliberately not scored (compressed container, see [tool support](tool-support.md#known-limitation-compressed-containers-and-yara)) | `mobile_df.benchmark` |
| FAT12 image (`training-fat12.img`) | Exists | `NOTE.TXT` listed and recovered; its 2026-09-20 modification time in the timeline; YARA marker in recovered file | `image_file`, `image_file_time` (image cases); benchmark; installed-tool test |
| Raw split FAT12 image | Exists (#11) | Every segment hashed, copied and verified; real Sleuth Kit reads it; a missing segment is named as the reason | `test_segments.py` |
| NIST CFReDS NTFS `ntfs1-gen1.E01` (public test image, not committed) | Verified on E1 | 39 Sleuth Kit entries, 55 timeline events, ExifTool `partial` for the 4 EFS-encrypted files | Recorded in [evaluation.md](evaluation.md#nist-ntfs-e01-test-image); not yet an `expected.json` |
| MVT bugreport extraction | **To build** | To define with MVT's documented bugreport layout | New expectation keys + evaluator checks |
| MVT AndroidQF extraction | **To build** | As above for AndroidQF | As above |
| ext4 (and later F2FS) image | **To build** | Allocated file list and one recovered file at a known partition offset; Android uses these, while FAT12 and NTFS are verified so far | `image_file`, `image_file_time`, plus offset parameter |
| Real multi-segment E01 set | **To obtain** | All segments copied and verified; listing succeeds once every segment is present | Status and `image_file` |
| Larger SQLite set (several app schemas, >`max_rows` rows) | **To build** | Row counts, `partial` status when the limit is hit | New count checks |
| Encrypted / unsupported input | In review (#10) | Visible failure or warning, never a silent empty result: encrypted ZIP, damaged/truncated archives, corrupt SQLite, encrypted `.ab`, empty folder | `test_input_handling.py` |

Each new fixture is added in its own PR with: the generator, its `expected.json`, evaluator support for any new key, and a test that runs it on E2 with the tools available there.

## 6. Manual desktop checklist

Run on E1 before each milestone and for any PR that changes `desktop.py`. Record date, commit and result in [evaluation.md](evaluation.md).

1. `.\start-desktop.ps1` opens; the home setup checklist and the Tool readiness screen match `python -m mobile_df.registry` (tools, versions, licences).
2. New investigation on the demo evidence with all tools ticked; progress bar and per-tool states update; case reaches `completed` or `completed_with_warnings` with a reason.
3. Not-installed tools are disabled in the tool checkboxes.
4. Cancel during a long tool: the tool stops, remaining tools show skipped, case is saved as `cancelled` with a report.
5. Close the app during analysis, reopen: case shows `incomplete`; re-run creates a new case with the same options; the interrupted folder is kept.
6. Case review: filter findings by source, severity and text; filter timeline by date prefix; CSV export opens in a spreadsheet with no formulas executed.
7. Settings: invalid timeout or missing YARA file is refused and nothing is saved; a valid YARA file makes YARA run on the next case.
8. Archive, restore, then delete a case after confirmation; original evidence is untouched (re-hash it).
9. Export handoff ZIP, then `python -m mobile_df.handoff verify` passes; edit one byte in the ZIP copy and verify fails.
10. Open the report from the desktop; it renders with no script errors in the browser console.
11. TOOL RUNS tab: select a tool and choose **View logs**; stdout/stderr for that run appear; a failed tool's log shows why it failed.
12. Tool readiness: **Verify tool packs** reports each pack as matching its pinned SHA-256 (compare with `python -m mobile_df.registry --verify`); a deliberately altered copy of a pack in a scratch install is reported as a mismatch.
13. Tool readiness: **Licence notices** opens and lists every installed third-party tool with its licence (compare with `python -m mobile_df.registry --notices`).
14. Tool readiness: **Install / update** (or **Install from offline kit** on E3) into a scratch install; cancelling midway leaves the previous install working.

## 7. Entry and exit criteria

A pull request is ready for review when:

- `.\scripts\test.ps1` passes on the author's machine, and the PR says which environment (E1/E2) was used;
- new behaviour has a test, or the PR explains why it cannot and which manual checklist step covers it;
- no evidence, case output or credentials are included.

A milestone is accepted when:

- the full suite passes on E1 with the installed-tool test **run, not skipped**;
- the full suite passes on E2;
- `python -m mobile_df.benchmark --runs 3` on E1 gives `pass` for every case in every run, with identical findings across runs. (The extraction demo skips `image_file` and `image_file_time` by design; the benchmark's image case scores them.);
- the manual checklist is complete with results recorded;
- known gaps are listed in [evaluation.md](evaluation.md) under "Remaining evaluation".

## 8. Known gaps and risks

| Gap | Risk | Plan |
|---|---|---|
| No continuous integration | A test that only passes on one machine can be merged | Add a GitHub Actions workflow running the suite on Windows and Ubuntu (needs a maintainer or a token with `workflow` scope) |
| ~~MVT `sms` output name assumed by the evaluator~~ | **Closed:** `mvt_sms_rows` passed in all three benchmark runs on E1 with MVT 2026.9.7 ([evaluation.md](evaluation.md#repeated-controlled-benchmark-18-november-2026)) | Re-check whenever the pinned MVT version changes |
| Plaso not run for real | Real parser output may differ from the contract and simulated-Docker tests | Run on E4 (Docker image); add a fixture with expected events |
| Image analysis verified on FAT12 and NTFS (E01), not Android filesystems | Android ext4/F2FS behaviour unknown | ext4 fixture (section 5) |
| No real-device dataset | Accuracy claims cannot be made | Seek an authorised public Android reference dataset; record licence and provenance before use |
| Desktop GUI only smoke-tested (render test in `test_integrations.py`) | Regressions in clicks and dialogs found late | Manual checklist each milestone; keep logic in GUI-free modules with tests |
| Peak memory and disk use not measured | Large evidence may exhaust a workstation | Add to the benchmark in May – Jul (section 9) |

## 9. Schedule (aligned with the roadmap)

| Period | Deliverable |
|---|---|
| Nov 2026 – Jan 2027 | This plan; fixture evaluator (done); four-case benchmark (done, #9); encrypted/unsupported input tests (#10); MVT bugreport/AndroidQF and ext4 fixtures; first full E1 and E2 runs recorded |
| Feb – Apr 2027 | Functional and coverage results per adapter; larger SQLite set; real Plaso run on E4 |
| May – Jul 2027 | Performance and reliability study built on `mobile_df.benchmark` (`benchmark.json` / `benchmark.md` already give per-case and per-tool run time and repeated-run stability): add peak memory and disk use, and larger fixture sizes |
| Aug – Sep 2027 | Release checks, installation guide test on a clean machine (E3), final evaluation report for the 50% gate |

## 10. Reporting defects

Use the GitHub bug report form. Include the environment ID, commit, command, `status` of each tool run from `results.json`, and the relevant `logs/` excerpt. Never attach evidence, reports from real cases, or unsanitised logs.
