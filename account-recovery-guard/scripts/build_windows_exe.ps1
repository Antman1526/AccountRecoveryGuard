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
$PyinstallerArgs = @(
  "--onefile",
  "--name", "AccountRecoveryGuard",
  "--clean",
  "--windowed"
)

& $PythonExe -m PyInstaller @PyinstallerArgs packaging/account_recovery_guard_entry.py

if ($env:WINDOWS_SIGNTOOL_PATH -and $env:WINDOWS_CERT_SHA1) {
  & $env:WINDOWS_SIGNTOOL_PATH sign /sha1 $env:WINDOWS_CERT_SHA1 /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 dist\AccountRecoveryGuard.exe
}

& $PythonExe scripts\checksums.py dist\AccountRecoveryGuard.exe | Out-File -Encoding ascii dist\AccountRecoveryGuard.exe.sha256

Write-Host "Created dist\AccountRecoveryGuard.exe"
