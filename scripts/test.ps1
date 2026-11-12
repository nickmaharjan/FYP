$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONPATH = Join-Path (Get-Location) 'src'
& '.venv/Scripts/python.exe' -m unittest discover -s tests -v
exit $LASTEXITCODE
