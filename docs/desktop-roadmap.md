# Desktop conversion: first 10% and team plan

This is the proposed conversion plan for the four-person team named in the project proposal. Task ownership is a suggested allocation, not a claim that those members have completed the work.

## Completed first 10% foundation

- Added a native Windows desktop entry point using Python's built-in Tkinter.
- Reused the existing local analysis pipeline and tool discovery instead of duplicating forensic code.
- Added an investigation home, recent case list, tool readiness view, evidence pickers, background analysis, and a report-opening action.
- Added `start-desktop.ps1`; the browser dashboard can remain available while the native desktop conversion proceeds.
- Applied the visual redesign detailed below to both the desktop shell and the existing browser interface.

This is an initial development shell. It does not yet package a Windows installer, install or update third-party tools, isolate privileged binaries, or provide production release handling.

## Case management increment (November 2026)

- Searchable case library: lists every case folder, newest first, with status, evidence integrity, finding count and start time. Interrupted analyses appear as `incomplete` instead of being hidden.
- In-app case review: double-click a case to see headline metrics, integrity and warnings, with tabs for findings (filter by source, severity and text; JSON detail pane), UTC timeline (ISO date-prefix range and text search), cross-tool correlations, and per-tool run outcomes.
- Filtered findings export to CSV, with spreadsheet-formula neutralization.
- Cancel a running analysis from the desktop: the current tool process is stopped, remaining tools are skipped, and a partial `cancelled` case and report are still saved.
- Case-library logic lives in `src/mobile_df/case_library.py` (no GUI dependency) and is covered by `tests/test_case_library.py`.

## Desktop workflow increment (November 2026)

- Live analysis progress: a progress bar, elapsed time, and a per-tool state (waiting, running, success with finding count, partial, failed, timeout, skipped). Tools that do not apply to the evidence type are shown as skipped. Logic: `src/mobile_df/progress.py`.
- Per-case tool selection: the new-case form has a checkbox per tool; tools that are not installed are disabled.
- Settings screen, saved to `data/settings.json` (ignored by Git): case data folder, YARA rules file, indicators file, tool timeout, SQLite row limit, image sector offset, and default tool selection. Values are validated before saving. Before this change the desktop never passed a YARA rules file, so YARA was always skipped in desktop analyses. Logic: `src/mobile_df/settings.py`.
- Case archive: archive and restore cases (moved to `<case data folder>/_archive`, nothing deleted) and permanently delete a case workspace after confirmation. Delete only accepts a case folder directly inside the case library or its archive; original evidence is never inside a case folder and is not touched.
- Covered by `tests/test_desktop_workflow.py`, including a check that the progress model matches real pipeline messages.
- Re-run interrupted cases: the pipeline now writes `status.json` before any tool runs, recording the evidence path, tools, limits, YARA rules and indicators. Opening an `incomplete` case in the desktop offers to re-run it with exactly those options in a new case folder; the interrupted folder is kept for archive or deletion. Re-run is refused, with the reason, when the evidence or rules have moved, or when the case predates this change. Logic: `rerun_options()` in `src/mobile_df/case_library.py`; tests: `tests/test_resume.py`.
- Case handoff: **Export handoff ZIP** on the case review screen (and `python -m mobile_df.handoff export|verify`) packages a finished case with a per-file SHA-256 manifest and a `.sha256` file for the ZIP, so a recipient can verify nothing changed. Evidence working copies are never packaged; native tool output is opt-in. Logic: `src/mobile_df/handoff.py`; tests: `tests/test_handoff.py`.

## Milestone integration increment (18 November 2026)

Cross-stream work toward the 50% gate (each line names the stream it advances):

- Forensic integrations: The Sleuth Kit adapter now reads `fls -m` body files, so disk images get a real timeline (MACB-labelled modified/accessed/changed/created times), deleted entries are flagged, NTFS `$FILE_NAME` times are kept, and a `$STANDARD_INFORMATION`-before-`$FILE_NAME` creation time is reported as a review lead. FAT times are read as UTC so results do not depend on the examiner's time zone.
- Forensic integrations: clear failure states. ExifTool per-file errors (for example encrypted files) make the run `partial` with the count and file names, instead of `failed`; step-level reasons now reach the tool run.
- Dependency manager: `tool-packs.json` is the single list of pinned packs for `setup.ps1` and the new `mobile_df.registry` (tool purpose, licence, install source, detected version, pack SHA-256 verification, licence notices). Every case records each tool's version.
- Verification and evaluation: `mobile_df.benchmark` repeats both controlled fixtures, scores them, and writes accuracy and timing tables; a new `image_file_time` expectation checks image timestamps. Results are in [evaluation](evaluation.md).
- Desktop: **View logs** on the TOOL RUNS tab (command, exit code, stderr/stdout tail, read only from the case logs folder), tool versions per run, and a Tool readiness screen with versions, pinned pack versions, licences, **Verify tool packs** and **Licence notices**.
- Documentation: [installation guide](installation.md) with online/offline install, checks, first controlled case and troubleshooting.
- Tests: `tests/test_integrations.py` (52 tests in total).

Gate status after this increment: create/resume/review is in place; documented install with verified packs exists but there is no in-app install/update yet; adapters log versions and distinguish partial from failed, but Plaso still has no real runtime; a reproducible controlled evaluation and installation guide exist, but real Android datasets are still needed.

## Installer, Plaso runtime and fixtures increment (18 November 2026)

- Dependency manager: in-app install, update and repair of the pinned tool packs (`mobile_df.installer`, desktop Tool readiness buttons with progress and cancel, offline kit support). HTTPS-only downloads, SHA-256 checked before unpacking, unpack beside the old copy and swap only when complete, path-traversal-safe unpacking, `tools.local.json` updated without losing other entries, installed versions recorded.
- Forensic integrations: Plaso runs through the official Docker image with read-only evidence, no network and container-path mapping, so Windows hosts have a supported Plaso route. Not yet run against the real image here (Docker not running).
- Verification and evaluation: ZIP export and Android `.ab` backup fixtures; the benchmark now covers four evidence types, all passing 3/3 runs. Documented that YARA cannot see inside compressed backups.
- Desktop usability: a setup checklist on the home screen (tool packs, YARA/MVT, YARA rules, writable case folder, optional Plaso) with links to fix each item; it disappears when everything is done.
- Tests: `tests/test_installer_plaso.py` (61 tests in total).

Gate status: (1) create/resume/review: done. (2) discover and install supported tools through documented local flows: done for the portable packs; Python packages still come from `setup.ps1`. (3) adapters with logged versions and clear failure states: done, except a real Plaso run still needs to be recorded. (4) reproducible controlled evaluation and installation guide: done for synthetic fixtures; real authorised Android datasets and a clean-machine install test remain.

## Proposed work split to reach 50% by September 20, 2027

Current planning date: November 11, 2026. The earlier September 20, 2026 date has passed; this plan assumes the next September 20 checkpoint. By that checkpoint, finish desktop case management, tool setup and compatibility, integrated analysis/report review, and the first evaluation/release candidate. Treat each stream as roughly 10% of the total product, for a combined 40% after the current 10% shell.

| Member | Proposed ownership | Checkpoints |
|---|---|---|
| Nick Maharjan | Desktop shell and case management: navigation, case library, progress/cancel, settings, error recovery, native report handoff | Nov 2026-Jan 2027: workflows and interaction spec; Feb-Apr: case lifecycle; May-Jul: usability fixes; Aug-Sep: integration and handoff |
| Niraj Bam | Dependency manager: detect versions, permitted tool packs, install/update paths, checksums, license notices, offline setup | Nov 2026-Jan 2027: platform/license matrix; Feb-Apr: detector and tool registry; May-Jul: install/update packs; Aug-Sep: verify package states and offline flow |
| Roshan Rauniyar | Forensic integrations: adapter compatibility, Plaso runtime path, cancellation/logs, normalized output and evidence provenance | Nov 2026-Jan 2027: adapter matrix and fixtures; Feb-Apr: adapter upgrades; May-Jul: Plaso and cross-tool correlation; Aug-Sep: compatibility pass |
| Sachin Gautam | Verification and evaluation: controlled datasets, expected findings, accuracy/resource measures, documentation and packaging QA | Nov 2026-Jan 2027: test plan and datasets; Feb-Apr: functional/coverage results; May-Jul: performance/reliability study; Aug-Sep: docs, release checks and report |

## 50% completion gate for September 20, 2027

Count the milestone as reached only when the four streams deliver together: the desktop app can create, resume and review a case; a user can discover and install supported licensed tools through documented local flows; all enabled adapters execute with logged versions and clear failure states; and a reproducible controlled evaluation plus installation guide is ready. A schedule or assignment alone does not count as delivered progress.

## UI redesign, one line per change

- Decorative gradients: removed; all surfaces use solid graphite colors.
- Accent: replaced teal with high-contrast acid yellow-green on charcoal, avoiding blue-white and the usual cream/terracotta palette.
- Cards: removed drop shadows and outlined card styling; content is grouped in flat bands and unboxed sections.
- Icons: removed decorative symbols next to text labels; status is shown as plain text.
- Layout: replaced the card dashboard and centered hero with a left navigation rail, a broad casework area, and a narrow tool-readiness column.

## Start the desktop prototype

From PowerShell in the project folder, run `.\start-desktop.ps1`. The GUI uses the existing `.venv`, `.tools`, and `tools.local.json`. The web dashboard remains at the separate `start.ps1` entry point during this first conversion stage.
