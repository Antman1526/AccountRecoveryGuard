#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BOOTSTRAP="${PYTHON:-python3}"
BUILD_VENV="${BUILD_VENV:-.build-venv}"

create_dmg_with_retries() {
  local attempt
  for attempt in 1 2 3; do
    rm -f "$DMG_PATH"
    if hdiutil create \
      -volname "AccountRecoveryGuard" \
      -srcfolder "$DMG_ROOT" \
      -ov \
      -format UDZO \
      "$DMG_PATH"; then
      return 0
    fi
    if [[ "$attempt" -lt 3 ]]; then
      echo "hdiutil create failed on attempt $attempt; retrying after cleanup..." >&2
      hdiutil detach "$DMG_ROOT" -force >/dev/null 2>&1 || true
      sleep $((attempt * 3))
    fi
  done
  return 1
}

"$PYTHON_BOOTSTRAP" -m venv "$BUILD_VENV"
PYTHON_BIN="$BUILD_VENV/bin/python"

"$PYTHON_BIN" -m pip install --upgrade pip
"$PYTHON_BIN" -m pip install -r requirements-build.txt
"$PYTHON_BIN" -m pip install -e .

rm -rf build dist
PYINSTALLER_ARGS=(
  --name AccountRecoveryGuard
  --clean
  --windowed
)

if [[ -n "${MACOS_CODESIGN_IDENTITY:-}" ]]; then
  PYINSTALLER_ARGS+=(--codesign-identity "$MACOS_CODESIGN_IDENTITY")
  PYINSTALLER_ARGS+=(--osx-entitlements-file packaging/macos-entitlements.plist)
  SIGNING_STATUS="signed"
else
  SIGNING_STATUS="unsigned-development"
fi

"$PYTHON_BIN" -m PyInstaller "${PYINSTALLER_ARGS[@]}" packaging/account_recovery_guard_entry.py

DMG_ROOT="dist/dmg-root"
DMG_PATH="dist/AccountRecoveryGuard-macOS.dmg"
rm -rf "$DMG_ROOT" "$DMG_PATH"
mkdir -p "$DMG_ROOT"
if [[ -d "dist/AccountRecoveryGuard.app" ]]; then
  cp -R "dist/AccountRecoveryGuard.app" "$DMG_ROOT/AccountRecoveryGuard.app"
else
  cp "dist/AccountRecoveryGuard" "$DMG_ROOT/AccountRecoveryGuard"
fi
cp README.md "$DMG_ROOT/README.md"
if [[ -L "$DMG_ROOT/Applications" ]]; then
  rm "$DMG_ROOT/Applications"
elif [[ -e "$DMG_ROOT/Applications" ]]; then
  echo "$DMG_ROOT/Applications already exists and is not a symlink" >&2
  exit 1
fi
ln -s /Applications "$DMG_ROOT/Applications"

create_dmg_with_retries

"$PYTHON_BIN" scripts/checksums.py "$DMG_PATH" > "dist/AccountRecoveryGuard-macOS.dmg.sha256"
"$PYTHON_BIN" scripts/artifact_integrity.py verify "$DMG_PATH" "dist/AccountRecoveryGuard-macOS.dmg.sha256"
"$PYTHON_BIN" scripts/artifact_integrity.py manifest \
  "$DMG_PATH" \
  "dist/AccountRecoveryGuard-macOS.dmg.sha256" \
  --platform macos \
  --signing-status "$SIGNING_STATUS" \
  --output "dist/AccountRecoveryGuard-macOS.manifest.json"
echo "Created $DMG_PATH"
