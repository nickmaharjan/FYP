# Contributing

Thanks for helping improve Mobile DF Automation. Keep changes focused, reviewable, and safe for forensic evidence.

## Before you start

- Read the [README](README.md), [architecture guide](docs/architecture.md), and [tool support notes](docs/tool-support.md).
- Set up a local Windows environment with `.\scripts\setup.ps1`. The first setup downloads dependencies and portable tools; see the README for requirements.
- Use synthetic or authorized test evidence only. Do not commit acquired phone data, reports, logs containing personal data, screenshots of evidence, or other case material.
- Keep `.venv/`, `.tools/`, `tools.local.json`, `data/`, and `output/` local. These paths are ignored by Git.
- Do not commit passwords, API tokens, private keys, or machine-specific paths.

## Branch and pull request flow

Start from the latest `master` and make a short-lived branch:

```powershell
git switch master
git pull --ff-only
git switch -c feature/short-description
```

Use `fix/short-description` for a bug fix. Make focused commits with clear messages. Push the branch and open a pull request targeting `master`:

```powershell
git push -u origin feature/short-description
```

Ask another team member to review the pull request before merging. Include the problem, the change, how it was checked, and any limitations. Link related issues when available. Avoid committing generated files or large binaries.

## Local checks

After setup, run the existing project checks before requesting review:

```powershell
.\scripts\test.ps1
```

If a check cannot be run, say why in the pull request and describe any manual review performed. Do not put real evidence in test fixtures; create small synthetic fixtures instead.

## Issues and sensitive reports

Use the GitHub issue forms for reproducible bugs and feature requests. Strip personal or case-specific information from logs before sharing them. Never upload a device image, extraction, report, or evidence archive to an issue. Report suspected vulnerabilities through GitHub's private security reporting feature if it is enabled for this repository.

## Licensing

There is currently no `LICENSE` file. The maintainers should agree on and add a license before distributing the project or accepting contributions from outside the team.
