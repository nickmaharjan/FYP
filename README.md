# Mobile DF Automation

A working local Android DFIR prototype based on the FYP proposal. It includes a browser dashboard, CLI, and the first native desktop workbench, with verified evidence copies, modular forensic tools, normalized findings, UTC timelines, cross-source correlations and reports.

**Six proposal tools are installed and verified on this Windows workspace:** SQLite, YARA, ExifTool, ALEAPP, MVT and The Sleuth Kit. A seventh adapter supports Plaso when a compatible runtime is installed; its command/parser contract is tested but its real runtime has not been verified here.

## Start the dashboard

Dependencies are already installed in this workspace. In PowerShell, from the project directory:

```powershell
.\start.ps1
```

Open the local URL printed in the terminal, including the session token after `#`. Keep that terminal running. Click **Run synthetic demo** for a complete example, or **New investigation** to supply an acquired evidence path. The dashboard shows tool progress, findings, timeline, correlations, evidence hashes and report downloads. Cases persist under `data/cases/`.

## Start the native desktop workbench

In PowerShell from the project folder:

```powershell
.\start-desktop.ps1
```

The desktop workbench uses Python's built-in Tkinter and the same local analysis engine. It includes a searchable investigation library, in-app case review (findings, timeline, correlations and tool runs with filters and CSV export), tool readiness, evidence selection with per-case tool choice, background analysis with live per-tool progress and cancellation, case archive/restore/delete, a settings screen (case folder, YARA rules, indicators, timeouts and limits), and report opening. Set a YARA rules file in Settings for YARA to run from the desktop. This is the initial desktop-conversion milestone: a packaged installer, tool installation/update flow, and release hardening are still planned. See [desktop conversion roadmap](docs/desktop-roadmap.md) for the proposed four-member schedule and 50% milestone.

The demo contains generated SMS, Chrome history, a PNG, a benign YARA marker, and a synthetic STIX2 domain indicator. Its detections are intentional training findings.

## Install on another Windows x64 machine

Step-by-step guide with checks and troubleshooting: [docs/installation.md](docs/installation.md).

Requires Python 3.10+ (tested with Python 3.12), Internet access during setup, and sufficient space for evidence working copies.

```powershell
.\scripts\setup.ps1
.\start.ps1
```

If Python is not on PATH, supply `-Python C:\path\to\python.exe` to setup. Setup installs pinned Python dependencies in `.venv`, downloads checked portable tool archives to `.tools`, and writes `tools.local.json`. It does not install system services or modify system PATH. Downloads retain upstream licenses. Plaso is an optional separate installation; see [tool support](docs/tool-support.md).

### Offline installation (no Internet on the analysis computer)

On a Windows x64 computer with Internet, build an offline kit (tool archives that passed their SHA-256 checks, plus prebuilt Python wheels):

```powershell
.\scripts\setup.ps1 -SavePacks E:\mobile-df-packs
```

Copy that folder and the project to the offline computer, which needs the same Python version as the kit was built with, then run:

```powershell
.\scripts\setup.ps1 -Offline -PackDir E:\mobile-df-packs
```

`-Offline` never uses the network: pip installs only from the kit's `wheels` folder, tool archives are copied from the kit and still checked against their pinned SHA-256, and setup stops with a clear message if anything is missing.

## CLI

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m mobile_df.cli doctor
.\.venv\Scripts\python.exe -m mobile_df.cli demo --output output\my-demo
.\.venv\Scripts\python.exe -m mobile_df.cli analyze C:\cases\android-extraction --output C:\results\CASE-001 --case-id CASE-001 --yara-rules C:\rules\android.yar --iocs C:\rules\indicators.json
```

To score a case against a controlled fixture's expected findings (the demo writes `fixture/expected.json` and saves `case/evaluation.json` automatically):

```powershell
.\.venv\Scripts\python.exe -m mobile_df.cli evaluate output\my-demo\case --expected output\my-demo\fixture\expected.json --output output\my-demo\evaluation-rerun.json
```

To run both controlled fixtures several times and get accuracy and timing tables for the evaluation chapter:

```powershell
.\.venv\Scripts\python.exe -m mobile_df.benchmark --output output\bench-run --runs 3
```

It writes `benchmark.json` and `benchmark.md` (verdicts, check pass rate, wall time, per-tool time, findings, tool versions).

To install, update or repair the portable tools without the setup script (also available as buttons on the desktop Tool readiness screen):

```powershell
.\.venv\Scripts\python.exe -m mobile_df.installer install all
```

To list tools, versions and licences, or check downloaded packs against their pinned SHA-256:

```powershell
.\.venv\Scripts\python.exe -m mobile_df.registry
.\.venv\Scripts\python.exe -m mobile_df.registry --verify
```

Each expectation is reported as `pass`, `fail`, `skipped` (with the reason, e.g. the tool was unavailable) or `unsupported`. The command exits 0 only for a `pass` verdict, so it can gate CI or release checks. See [evaluation results](docs/evaluation.md#expected-findings-evaluation).

The output directory must be new and separate from evidence. `--tools sqlite yara aleapp` selects a subset. `--timeout 600` controls each subprocess; `--max-rows 2000` controls SQLite row export. Image analysis supports `--image-offset` in sectors and attempts allocated-file recovery with `tsk_recover` before other tools. Supply a known partition offset for partitioned disk images; the default is zero for filesystem images.

Accepted inputs: extraction directories, ZIP/TAR archives, raw and EnCase (E01) disk images supported by The Sleuth Kit (including split sets: choose the first segment, `.E01` or `.001`, with the others in the same folder), and Android `.ab` backups supported by MVT. MVT chooses backup mode for a directory containing `apps`; use `--mvt-mode bugreport` or `--mvt-mode androidqf` for those extraction types. MVT backup mode focuses on SMS/MMS and is not a general Android filesystem analyzer. This prototype analyzes acquired evidence; it does not acquire or unlock phones.

## Case outputs

| File / directory | Contents |
|---|---|
| `report.html` | Self-contained interactive report; open in a browser |
| `results.json` | Full normalized results, tool status, parameters, metrics and correlations |
| `timeline.csv` | UTC events with finding IDs and conversion basis |
| `manifest.json` | Original evidence SHA-256 hashes, paths, sizes and modification times |
| `audit.jsonl` | Timestamped processing activity |
| `logs/` | Commands' stdout and stderr; subprocess details are in results |
| `tools/` | Native tool outputs, recovered files and case-local MVT settings |
| `working/` | Verified copies used for analysis |

Raw tool output is retained even if parsing fails. Missing tools, incompatible inputs, timeouts, errors, disabled tools and truncation are visible. Reports preserve original values and source provenance. Correlations represent exact shared values and require investigator interpretation.

## Hand off a case

To give a finished case to a supervisor or colleague, open it in the desktop app and click **Export handoff ZIP**, or run:

```powershell
.\.venv\Scripts\python.exe -m mobile_df.handoff export data\cases\<case-folder> E:\CASE-001-handoff.zip
```

The ZIP contains the report, results, timeline, evidence hash manifest, audit log, tool logs and the rules or indicators used, plus `HANDOFF-MANIFEST.json` with the SHA-256 of every packaged file. A `.sha256` file with the ZIP's own hash is saved next to it; send both. Evidence working copies are never included, and native tool output (which can contain recovered evidence files) is only included when you choose it. The recipient verifies the package with:

```powershell
.\.venv\Scripts\python.exe -m mobile_df.handoff verify E:\CASE-001-handoff.zip
```

## Verify and extend

```powershell
.\scripts\test.ps1
```

The suite includes actual installed-tool analysis, SQLite WAL recovery, evidence-change detection, archive traversal/size protection, tool failure isolation, timeout/cancel behavior, report escaping and API access checks. Installed-tool tests skip explicitly if dependencies are absent.

See [architecture and adapter guide](docs/architecture.md), [tool support and upstream references](docs/tool-support.md), and [evaluation results](docs/evaluation.md). The dashboard and reports are implemented with Python's standard library and local HTML/CSS/JavaScript. No hosted services or API keys are required.

## Contributing

Team members can work in short-lived branches and submit pull requests to `master` for another member to review. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a change. Never commit acquired device evidence, case outputs, local tool configuration, or credentials. The repository does not yet include a `LICENSE`; agree on licensing before distributing or accepting broader external contributions.
