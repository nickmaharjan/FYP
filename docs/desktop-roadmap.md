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
