# Installation guide (Windows x64)

This guide installs Mobile DF Automation and its forensic tools on a Windows 10/11 x64 computer, checks that the installed tools are the tested versions, and runs a first controlled case. It takes about 10 minutes online.

## 1. Requirements

| Item | Needed |
|---|---|
| Windows | 10 or 11, 64-bit |
| Python | 3.10 or newer (3.12 tested), from python.org; tick *Add python.exe to PATH* |
| Disk space | About 350 MB for tools and Python packages, plus room for case working copies (each case copies its evidence) |
| Internet | Only for the online install, or once on another computer to build an offline kit |
| Rights | A normal user account; administrator rights are not needed |

## 2. Get the project

```powershell
git clone https://github.com/nickmaharjan/FYP.git Mobile-DF-Automation
cd Mobile-DF-Automation
```

If PowerShell refuses to run scripts, allow local scripts for your user once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## 3. Install (online)

```powershell
.\scripts\setup.ps1
```

The script:

1. creates `.venv` and installs the Python packages in `requirements-forensics.txt` (yara-python, MVT);
2. downloads the portable tool packs listed in `tool-packs.json` (ALEAPP, The Sleuth Kit, ExifTool) into `.tools`;
3. refuses any pack whose SHA-256 differs from the pinned value, so only the tested release is installed;
4. writes `tools.local.json` pointing at the installed tools;
5. prints the tool registry: each tool, whether it is ready, its version and its licence.

Use `-Python C:\path\to\python.exe` if Python is not on PATH.

## 4. Install without Internet (offline kit)

On a computer with Internet, build a kit on a USB drive:

```powershell
.\scripts\setup.ps1 -SavePacks E:\mobile-df-packs
```

On the analysis computer, with the project folder copied over:

```powershell
.\scripts\setup.ps1 -Offline -PackDir E:\mobile-df-packs
```

The offline install never uses the network and applies the same SHA-256 checks.

## 5. Check the installation

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m mobile_df.registry            # tools, versions, licences
.\.venv\Scripts\python.exe -m mobile_df.registry --verify   # downloaded packs match tool-packs.json
.\.venv\Scripts\python.exe -m mobile_df.registry --notices  # third-party licence notices
```

Expected on a complete install: SQLite, YARA, ExifTool, ALEAPP, MVT and The Sleuth Kit show `yes`; Plaso shows `no` (it needs a separate Linux environment, see [tool support](tool-support.md#configuration)). `--verify` reports `verified` for each pack and exits 0. The desktop shows the same information under **Tool readiness**, with **Verify tool packs** and **Licence notices** buttons.

## 6. First controlled case

```powershell
.\.venv\Scripts\python.exe -m mobile_df.benchmark --output output\bench-first --runs 1
```

This builds the synthetic fixtures, analyses the Android-shaped extraction and the FAT12 image, and scores both against the expected findings. Every verdict should be `pass`; checks for tools you have not installed are `skipped`, never counted as passes.

Then start the desktop:

```powershell
.\start-desktop.ps1
```

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `Checksum mismatch for .tools\<tool>.zip` | The download is incomplete or not the tested release. Delete that `.zip` and run setup again. |
| A tool shows `MISSING` in Tool readiness | Run setup again, or set its command in `tools.local.json` (see `tools.example.json`), then click **Re-check tools**. |
| A tool run is `failed` or `partial` in a case | Open the case, go to **TOOL RUNS**, select the tool and click **View logs** to see the command, exit code and the tool's own error output. |
| `Possible encryption detected` from The Sleuth Kit | The image (or the partition at the given offset) is encrypted or not a supported filesystem. Check the image offset in Settings. |
| Updating a tool | Change its `version`, `url` and `sha256` together in `tool-packs.json` after testing, delete the old pack from `.tools`, and run setup. |

## Licences

Each tool keeps its own licence (shown by `--notices` and in the desktop). The tools are downloaded separately and are not relicensed by this project. Review the MVT licence before redistributing a bundle that includes MVT.
