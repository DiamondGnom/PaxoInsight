$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$WorkspaceRoot = Split-Path -Parent $ProjectRoot
$DefaultBasePython = Join-Path $WorkspaceRoot ".python314\python.exe"
$BasePython = if ($env:PAXOINSIGHT_PYTHON314) {
    $env:PAXOINSIGHT_PYTHON314
} else {
    $DefaultBasePython
}
$EnvironmentRoot = Join-Path $WorkspaceRoot ".venv314"
$EnvironmentPython = Join-Path $EnvironmentRoot "Scripts\python.exe"
$Requirements = Join-Path $ProjectRoot "requirements-build.lock.txt"

if (-not (Test-Path -LiteralPath $BasePython)) {
    throw "CPython 3.14 was not found: $BasePython"
}

$Version = & $BasePython -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0 -or $Version.Trim() -ne "3.14") {
    throw "Expected standard CPython 3.14; found: $Version"
}
& $BasePython -c "import sys; raise SystemExit(0 if getattr(sys, '_is_gil_enabled', lambda: True)() else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "The free-threaded Python build is not supported"
}

if (-not (Test-Path -LiteralPath $EnvironmentPython)) {
    & $BasePython -m venv $EnvironmentRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the Python 3.14 environment"
    }
}

& $EnvironmentPython -m pip install --upgrade --requirement $Requirements
if ($LASTEXITCODE -ne 0) {
    throw "Could not install the locked build dependencies"
}
& $EnvironmentPython -m pip install --no-deps --no-build-isolation --editable $ProjectRoot
if ($LASTEXITCODE -ne 0) {
    throw "Could not install PaxoInsight into the build environment"
}
& $EnvironmentPython -m pip check
if ($LASTEXITCODE -ne 0) {
    throw "The Python 3.14 environment has broken dependencies"
}

Write-Host "Python 3.14 environment: $EnvironmentPython"
