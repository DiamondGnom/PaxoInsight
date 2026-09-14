$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$WorkspaceRoot = Split-Path -Parent $ProjectRoot
$DefaultPython = Join-Path $WorkspaceRoot ".venv314\Scripts\python.exe"
$Python = if ($env:PAXOINSIGHT_BUILD_PYTHON) {
    $env:PAXOINSIGHT_BUILD_PYTHON
} else {
    $DefaultPython
}
$LegacyRoot = Join-Path $WorkspaceRoot ".inspection_v5_1_0\PaxoInsight_v5.1.0_Portable"
$SourceRoot = Join-Path $ProjectRoot "src"
$BuildRoot = Join-Path $ProjectRoot "build\python314"
$DistRoot = Join-Path $ProjectRoot "dist\python314"

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Python 3.14 build environment not found: $Python"
}
if (-not (Test-Path -LiteralPath (Join-Path $LegacyRoot "PaxoInsight.py"))) {
    throw "PaxoInsight v5.1.0 analysis backend not found: $LegacyRoot"
}

$Version = & $Python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0 -or $Version.Trim() -ne "3.14") {
    throw "PaxoInsight must be built with standard CPython 3.14; found: $Version"
}
& $Python -c "import sys; raise SystemExit(0 if getattr(sys, '_is_gil_enabled', lambda: True)() else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "The free-threaded Python build is not supported; use standard CPython 3.14"
}
& $Python -m pip check
if ($LASTEXITCODE -ne 0) {
    throw "The Python 3.14 build environment has broken dependencies"
}

# Never expose the legacy v5.1 lib directory here: it contains CPython 3.12
# native extensions.  The spec locates only the pure-Python analyzer module.
$env:PYTHONPATH = $SourceRoot
Set-Location $ProjectRoot

& $Python -m PyInstaller `
    --noconfirm `
    --clean `
    --workpath $BuildRoot `
    --distpath $DistRoot `
    .\PaxoInsight.spec
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE"
}

$Distribution = Join-Path $DistRoot "PaxoInsight"
$Executable = Join-Path $Distribution "PaxoInsight.exe"
if (-not (Test-Path -LiteralPath $Executable)) {
    throw "One-folder executable was not created: $Executable"
}

$ForbiddenRuntime = Get-ChildItem -LiteralPath $Distribution -Recurse -Force |
    Where-Object {
        $_.FullName -match '(?i)PySide|QtCore|Qt6|shiboken|python312|cp312'
    }
if ($ForbiddenRuntime) {
    $ForbiddenNames = ($ForbiddenRuntime | ForEach-Object FullName) -join "`n"
    throw "Forbidden Qt or CPython 3.12 files entered the build:`n$ForbiddenNames"
}

$Python314Dll = Get-ChildItem -LiteralPath $Distribution -Recurse -Filter "python314.dll"
if (-not $Python314Dll) {
    throw "python314.dll is missing from the portable build"
}

$SelfTest = Start-Process `
    -FilePath $Executable `
    -ArgumentList "--self-test" `
    -WindowStyle Hidden `
    -PassThru `
    -Wait
if ($SelfTest.ExitCode -ne 0) {
    throw "Portable self-test failed with exit code $($SelfTest.ExitCode)"
}
$GuiSelfTest = Start-Process `
    -FilePath $Executable `
    -ArgumentList "--gui-self-test" `
    -WindowStyle Hidden `
    -PassThru `
    -Wait
if ($GuiSelfTest.ExitCode -ne 0) {
    throw "Portable Tkinter/TkDnD self-test failed with exit code $($GuiSelfTest.ExitCode)"
}

$ReadmeTarget = Join-Path $Distribution "README.txt"
Copy-Item -LiteralPath (Join-Path $ProjectRoot "README.md") -Destination $ReadmeTarget -Force

$Zip = Join-Path $ProjectRoot "dist\PaxoInsight_v6.0_Python314_Portable.zip"
if (Test-Path -LiteralPath $Zip) {
    Remove-Item -LiteralPath $Zip -Force
}

# Antivirus scanners can briefly keep the newly created executable open after
# the self-test. Retry the packaging step instead of reporting a false failure.
$ArchiveCreated = $false
for ($Attempt = 1; $Attempt -le 5; $Attempt++) {
    try {
        Compress-Archive `
            -LiteralPath $Distribution `
            -DestinationPath $Zip `
            -CompressionLevel Optimal
        $ArchiveCreated = $true
        break
    } catch {
        if (Test-Path -LiteralPath $Zip) {
            Remove-Item -LiteralPath $Zip -Force
        }
        if ($Attempt -eq 5) {
            throw
        }
        Start-Sleep -Seconds 2
    }
}
if (-not $ArchiveCreated) {
    throw "Portable ZIP was not created: $Zip"
}

Write-Host "Portable build: $Executable"
Write-Host "Portable ZIP:   $Zip"
