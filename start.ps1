param([int]$Port = 8765)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$env:PYTHONPATH = Join-Path $PSScriptRoot 'src'
$pythonPath = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Run scripts/setup.ps1 first to create the project environment.'
}
& $pythonPath -m mobile_df.cli serve --port $Port
