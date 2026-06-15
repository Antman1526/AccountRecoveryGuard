from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

from .models import PasswordCandidate, VaultPreflight, VaultPreflightSummary
from .passwords import generate_password

TEST_URL = "https://example.invalid/account-recovery-guard"


def build_live_test_candidate(username: str) -> PasswordCandidate:
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    return PasswordCandidate(
        service_name=f"ARG-LIVE-TEST-{stamp}",
        username=username,
        url=TEST_URL,
        password=generate_password(),
        note="Account Recovery Guard live vault test entry. Safe to delete after verification.",
    )


def preflight(nordpass_export: Path | None = None) -> VaultPreflight:
    return VaultPreflight(
        bitwarden_cli_found=shutil.which("bw") is not None,
        bitwarden_session_present=bool(os.environ.get("BW_SESSION")),
        nordpass_export_present=nordpass_export.exists() if nordpass_export else None,
    )


def summarize_preflight(result: VaultPreflight) -> VaultPreflightSummary:
    blockers: list[str] = []
    if not result.bitwarden_cli_found:
        blockers.append("Bitwarden CLI not found")
    if not result.bitwarden_session_present:
        blockers.append("BW_SESSION is not set")
    if result.nordpass_export_present is False:
        blockers.append("NordPass export CSV not found")
    return VaultPreflightSummary(ready=not blockers, blockers=blockers)
