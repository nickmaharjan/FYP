# Tool support and upstream references

| Tool | Implemented workflow | Verified here |
|---|---|---|
| SQLite | Header-based discovery, schema and bounded row export, WAL-aware working copies, timestamps and entities | Yes, standard library; uncheckpointed WAL fixture |
| YARA | `yara-python` compilation and recursive file matching; rules, metadata, match offsets | Yes, 4.5.4 |
| ExifTool | Recursive JSON extraction for supported media/document extensions | Yes, 13.59 |
| ALEAPP | Filesystem extraction mode and TSV normalization; raw native reports retained | Yes, v2026.4.1 Windows CLI |
| MVT | Android backup, bugreport and AndroidQF command adapters; JSON artifacts and alerts; STIX2 input | Backup and synthetic indicator detection verified with 2026.9.7; other modes need datasets |
| The Sleuth Kit | `fls -m` body-file listing with modified/accessed/changed/created times on the timeline (MACB-labelled), deleted-entry flags, NTFS `$FILE_NAME` times and a `$STANDARD_INFORMATION`-before-`$FILE_NAME` creation lead; `tsk_recover -a` allocated-file recovery at a selected sector offset; raw and E01 images | Yes, 4.15.0; synthetic FAT12 image and NIST NTFS E01 test image |
| Plaso | `log2timeline` storage generation, `psort -o json_line` export and timeline normalization; native commands or the official Docker image (`plaso_docker_image`) with read-only evidence, no network and container-path mapping | Command/parser fixture and a simulated Docker runtime; the real image has not been run on this Windows host (Docker not running) |

An adapter being implemented does not imply every Android app/database/version is supported. Native tool output and logs remain available for review. ALEAPP's CLI can complete despite individual plugin errors; inspect its log for plugin-level failures. MVT can report partial module failures in its own output. Tools that are missing, disabled, incompatible, timed out or failed are distinguished in the case report.

## Versions, licences and pinned packs

`tool-packs.json` pins the portable packs (version, download URL, SHA-256). `scripts/setup.ps1` installs from it and `python -m mobile_df.registry --verify` checks the downloaded archives against it. Every case records each tool's version in `tool_availability` and in each tool run (`tool_version`), shown in the report and the desktop **TOOL RUNS** tab. Versions are read from the tool (`exiftool -ver`, `fls -V`, `log2timeline --version`), from the installed Python package (yara-python, MVT), or, for ALEAPP which has no version flag, from the pinned pack when the configured executable is the one setup unpacked.

## Clear failure states

A tool run is `partial` rather than `failed` when the tool processed the input but some items could not be read. ExifTool exits with code 1 if any single file is unreadable (for example NTFS-encrypted files); the run is now `partial` with a reason such as "ExifTool could not read 4 of 12 files (encrypted, corrupt or unsupported)", and the unreadable files are `warning` findings. A real failure (no output, crash, timeout) is still `failed` or `timeout`. In the desktop, **View logs** shows each step's command, exit code, stderr and stdout.

FAT and exFAT store local time without a time zone. The Sleuth Kit adapter reads them as UTC (`-z UTC`) so results do not depend on the examiner computer's time zone; adjust for the device's zone when interpreting FAT times.

## Known limitation: compressed containers and YARA

YARA matches bytes in the files it is given. An Android `.ab` backup is zlib-compressed, so rules do not match content inside it (the synthetic backup's marker is not found). MVT reads the backup's content instead. Extract a backup to a folder first if YARA should scan the app data.

## Configuration

Copy `tools.example.json` to `tools.local.json` and set only the commands you need. An explicit command is an array: `["/path/to/python", "/path/to/aleapp.py"]` works as well as `["/path/to/aleapp.exe"]`. Use absolute paths for script arguments. The Windows setup script creates the local configuration automatically. The installed Python MVT package is preferred so its settings can be isolated per case.

Plaso requires both `plaso` and `psort` commands. Install it in a supported Linux environment following its upstream guide, install this application there, and point both commands at that environment's executables. Do not configure Windows commands to pass host paths into a container without mount/path translation.

## Upstream documentation

- [ALEAPP usage and installation](https://github.com/abrignoni/ALEAPP)
- [MVT Android backup workflow and STIX2 input](https://docs.mvt.re/en/stable/android/backup/)
- [MVT source and license](https://github.com/mvt-project/mvt)
- [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/)
- [ExifTool Windows installation](https://exiftool.org/install.html)
- [ExifTool portable package used in testing](https://oliverbetz.de/pages/Artikel/ExifTool-for-Windows)
- [YARA Python API](https://yara.readthedocs.io/en/stable/yarapython.html)
- [Plaso installation](https://plaso.readthedocs.io/en/latest/sources/user/Installing-with-docker.html)
- [Plaso JSON-line export](https://github.com/log2timeline/plaso/blob/main/docs/sources/user/Using-psort.md)

Tools retain their own licenses. Downloaded executables and Python environments are excluded from source control; the platform does not relicense those tools. In particular, review MVT's usage license before distributing a bundled version.
