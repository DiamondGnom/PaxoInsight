param([string]$BuildVariant = "python3148")

$ErrorActionPreference = "Stop"
if ($BuildVariant -notmatch '^[a-z0-9][a-z0-9.-]{0,63}$') {
    throw "Invalid scoped build directory name"
}

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$WorkspaceRoot = Split-Path -Parent $ProjectRoot
$DefaultPython = Join-Path $WorkspaceRoot ".venv3148\Scripts\python.exe"
$Python = if ($env:PAXOINSIGHT_BUILD_PYTHON) {
    $env:PAXOINSIGHT_BUILD_PYTHON
} else {
    $DefaultPython
}
$SourceRoot = Join-Path $ProjectRoot "src"
$BuildRoot = Join-Path $ProjectRoot "build\$BuildVariant"
$DistRoot = Join-Path $ProjectRoot "dist\$BuildVariant"

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Python 3.14 build environment not found: $Python"
}
if (-not (Test-Path -LiteralPath (Join-Path $SourceRoot "paxoinsight\_vendor\analyzers.py"))) {
    throw "Bundled PaxoInsight analysis backend not found"
}

$env:PYTHONPATH = $SourceRoot
& $Python -c "from paxoinsight.runtime import require_supported_runtime; require_supported_runtime()"
if ($LASTEXITCODE -ne 0) {
    throw "Use standard CPython 3.14.8+ x64 with GIL"
}
& $Python -m pip check
if ($LASTEXITCODE -ne 0) {
    throw "The Python 3.14 build environment has broken dependencies"
}

# Analysis functions are bundled in src; old portable libraries are not used.
Set-Location $ProjectRoot
& $Python (Join-Path $PSScriptRoot "verify_desktop_build.py") --environment
if ($LASTEXITCODE -ne 0) {
    throw "Desktop environment does not match reviewed dependency locks"
}

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
& $Python (Join-Path $PSScriptRoot "verify_desktop_build.py") --distribution $Distribution
if ($LASTEXITCODE -ne 0) {
    throw "Frozen module/DLL/source identity validation failed"
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
$SecuritySelfTest = Start-Process `
    -FilePath $Executable `
    -ArgumentList @("--security-self-test", "--self-test-report", ('"' + (Join-Path $Distribution "SECURITY_SELF_TEST.json") + '"')) `
    -WindowStyle Hidden `
    -PassThru `
    -Wait
if ($SecuritySelfTest.ExitCode -ne 0) {
    throw "Portable security regression self-test failed: $($SecuritySelfTest.ExitCode)"
}

$ReadmeTarget = Join-Path $Distribution "README.txt"
Copy-Item -LiteralPath (Join-Path $ProjectRoot "README.md") -Destination $ReadmeTarget -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "CHANGELOG.md") -Destination $Distribution -Force
& $Python (Join-Path $PSScriptRoot "desktop_sbom.py") --distribution $Distribution
if ($LASTEXITCODE -ne 0) {
    throw "Artifact SBOM generation failed"
}
Copy-Item -LiteralPath (Join-Path $ProjectRoot "SBOM.cdx.json") -Destination $Distribution -Force

$AppVersion = & $Python -c "from paxoinsight import VERSION; print(VERSION)"
if ($LASTEXITCODE -ne 0) {
    throw "Cannot determine the application version"
}
$AppVersion = $AppVersion.Trim()
$Zip = Join-Path $ProjectRoot "dist\PaxoInsight_v${AppVersion}_Python3148_Portable.zip"
if (Test-Path -LiteralPath $Zip) {
    throw "Release ZIP already exists; preserve it and use a new version or output name: $Zip"
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
