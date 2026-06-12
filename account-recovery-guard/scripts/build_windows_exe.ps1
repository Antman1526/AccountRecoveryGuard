$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RootDir

$PythonBootstrap = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$BuildVenv = if ($env:BUILD_VENV) { $env:BUILD_VENV } else { ".build-venv" }
$PythonExe = Join-Path $BuildVenv "Scripts\python.exe"

& $PythonBootstrap -m venv $BuildVenv
& $PythonExe -m pip install --upgrade pip
& $PythonExe -m pip install -r requirements-build.txt
& $PythonExe -m pip install -e .

Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue
& $PythonExe -m PyInstaller `
  --onefile `
  --name AccountRecoveryGuard `
  --clean `
  packaging/account_recovery_guard_entry.py

Write-Host "Created dist\AccountRecoveryGuard.exe"
