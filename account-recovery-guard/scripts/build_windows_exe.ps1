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
  $SigningStatus = "signed"
} else {
  $SigningStatus = "unsigned-development"
}

& $PythonExe scripts\checksums.py dist\AccountRecoveryGuard.exe | Out-File -Encoding ascii dist\AccountRecoveryGuard.exe.sha256
& $PythonExe scripts\artifact_integrity.py verify dist\AccountRecoveryGuard.exe dist\AccountRecoveryGuard.exe.sha256
& $PythonExe scripts\artifact_integrity.py manifest dist\AccountRecoveryGuard.exe dist\AccountRecoveryGuard.exe.sha256 --platform windows --signing-status $SigningStatus --output dist\AccountRecoveryGuard-Windows.manifest.json
@"
Account Recovery Guard for Windows

This build opens the guided desktop app. Windows may ask you to confirm the app until it is signed with an Authenticode certificate.
"@ | Set-Content -Encoding ascii dist\README-Windows.txt

Write-Host "Created dist\AccountRecoveryGuard.exe"
