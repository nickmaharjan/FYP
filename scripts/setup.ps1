param([string]$Python = '')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot
$pythonPath = Join-Path $projectRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    if ($Python) {
        & $Python -m venv .venv
    } elseif (Get-Command py -ErrorAction SilentlyContinue) {
        py -3 -m venv .venv
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        python -m venv .venv
    } else {
        throw 'Install Python 3.10+ or pass -Python with the full path to python.exe.'
    }
    if ($LASTEXITCODE -ne 0) { throw 'Creating the virtual environment failed.' }
}
& $pythonPath -m pip install -r requirements-forensics.txt
if ($LASTEXITCODE -ne 0) { throw 'Installing Python dependencies failed.' }

$downloads = @(
    @{Name='aleapp'; Url='https://github.com/abrignoni/ALEAPP/releases/download/v2026.4.1/aleapp-v2026.4.1-Windows_x86_64.zip'; SHA256='8EB1AD25F9FDC89AF345277AD6FF748636E3552490E39A4FD379DEBDE0AF70FA'; Binary='aleapp/aleapp.exe'},
    @{Name='sleuthkit'; Url='https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.15.0/sleuthkit-4.15.0-win32.zip'; SHA256='C2EBAB8105B893D97BD8CE35B88E01985E2A106EFC97F03ADF95840A631B20CE'; Binary='sleuthkit/sleuthkit-4.15.0-win32/bin/fls.exe'},
    @{Name='exiftool'; Url='https://oliverbetz.de/cms/files/Artikel/ExifTool-for-Windows/exiftool-13.59_64.zip'; SHA256='577257DD22BAEBE77157D905792D6ED2C5916CD03AA627F40B2175DB12110AC6'; Binary='exiftool/ExifTool.exe'}
)
New-Item -ItemType Directory -Force -Path '.tools' | Out-Null
foreach ($download in $downloads) {
    $archive = Join-Path '.tools' ($download.Name + '.zip')
    if (-not (Test-Path -LiteralPath $archive)) {
        Write-Host "Downloading $($download.Name) from its upstream distribution..."
        Invoke-WebRequest -Uri $download.Url -OutFile $archive
    }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $download.SHA256) {
        throw "Checksum mismatch for $archive. The package is not the release tested with this prototype."
    }
    if (-not (Test-Path -LiteralPath (Join-Path '.tools' $download.Binary))) {
        Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path '.tools' $download.Name) -Force
    }
}
if (-not (Test-Path -LiteralPath 'tools.local.json')) {
    @{
        commands = @{
            aleapp = @((Join-Path $projectRoot '.tools/aleapp/aleapp.exe'))
            exiftool = @((Join-Path $projectRoot '.tools/exiftool/ExifTool.exe'))
            sleuthkit = @((Join-Path $projectRoot '.tools/sleuthkit/sleuthkit-4.15.0-win32/bin/fls.exe'))
            tsk_recover = @((Join-Path $projectRoot '.tools/sleuthkit/sleuthkit-4.15.0-win32/bin/tsk_recover.exe'))
        }
    } | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 'tools.local.json'
}
$env:PYTHONPATH = Join-Path $projectRoot 'src'
& $pythonPath -m mobile_df.cli doctor
Write-Host 'Setup complete. Run ./start.ps1 to launch the dashboard.'
