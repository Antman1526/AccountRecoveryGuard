#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BOOTSTRAP="${PYTHON:-python3}"
BUILD_VENV="${BUILD_VENV:-.build-venv}"

"$PYTHON_BOOTSTRAP" -m venv "$BUILD_VENV"
PYTHON_BIN="$BUILD_VENV/bin/python"

"$PYTHON_BIN" -m pip install --upgrade pip
"$PYTHON_BIN" -m pip install -r requirements-build.txt
"$PYTHON_BIN" -m pip install -e .

rm -rf build dist
"$PYTHON_BIN" -m PyInstaller \
  --onefile \
  --name AccountRecoveryGuard \
  --clean \
  packaging/account_recovery_guard_entry.py

DMG_ROOT="dist/dmg-root"
DMG_PATH="dist/AccountRecoveryGuard-macOS.dmg"
rm -rf "$DMG_ROOT" "$DMG_PATH"
mkdir -p "$DMG_ROOT"
cp "dist/AccountRecoveryGuard" "$DMG_ROOT/AccountRecoveryGuard"
cp README.md "$DMG_ROOT/README.md"

hdiutil create \
  -volname "AccountRecoveryGuard" \
  -srcfolder "$DMG_ROOT" \
  -ov \
  -format UDZO \
  "$DMG_PATH"

echo "Created $DMG_PATH"
