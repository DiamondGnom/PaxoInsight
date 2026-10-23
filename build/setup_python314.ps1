$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$WorkspaceRoot = Split-Path -Parent $ProjectRoot
$DefaultBasePython = Join-Path $WorkspaceRoot ".python3148\python.exe"
$BasePython = if ($env:PAXOINSIGHT_PYTHON314) {
    $env:PAXOINSIGHT_PYTHON314
} else {
    $DefaultBasePython
}
$EnvironmentRoot = Join-Path $WorkspaceRoot ".venv3148"
$EnvironmentPython = Join-Path $EnvironmentRoot "Scripts\python.exe"
$Requirements = Join-Path $ProjectRoot "requirements-build.hashes.txt"

if (-not (Test-Path -LiteralPath $BasePython)) {
    throw "CPython 3.14.8 x64 was not found: $BasePython"
}

$env:PYTHONPATH = Join-Path $ProjectRoot "src"
& $BasePython -c "from paxoinsight.runtime import require_supported_runtime; require_supported_runtime()"
if ($LASTEXITCODE -ne 0) {
    throw "Expected standard CPython 3.14.8+ x64 with GIL"
}

if (-not (Test-Path -LiteralPath $EnvironmentPython)) {
    & $BasePython -m venv $EnvironmentRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the Python 3.14 environment"
    }
}

& $EnvironmentPython -c "from paxoinsight.runtime import require_supported_runtime; require_supported_runtime()"
if ($LASTEXITCODE -ne 0) {
    throw "Existing environment uses an unsupported interpreter; do not reuse it"
}
if (-not (Test-Path -LiteralPath $Requirements)) {
    throw "Reviewed desktop hashes are missing; run build/lock_desktop_hashes.py first"
}
& $EnvironmentPython -m pip install --only-binary=:all: --require-hashes --requirement $Requirements
if ($LASTEXITCODE -ne 0) {
    throw "Could not install the locked build dependencies"
}
& $EnvironmentPython -m pip install --no-deps --no-build-isolation --editable $ProjectRoot
if ($LASTEXITCODE -ne 0) {
    throw "Could not install PaxoInsight into the build environment"
}
# PEP 660 may leave an older source-tree egg-info next to the editable package.
# Refresh this generated metadata before pip check and PyInstaller discovery.
Push-Location $ProjectRoot
try {
    & $EnvironmentPython -c "from setuptools import setup; setup(script_args=['egg_info'])"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not refresh generated source metadata"
    }
} finally {
    Pop-Location
}
& $EnvironmentPython -m pip check
if ($LASTEXITCODE -ne 0) {
    throw "The Python 3.14 environment has broken dependencies"
}

Write-Host "Python 3.14 environment: $EnvironmentPython"
