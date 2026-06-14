from __future__ import annotations

import os
import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class ReadinessCheck:
    name: str
    status: str
    detail: str


def build_readiness_checks(hibp_secret_name: str | None = None) -> tuple[ReadinessCheck, ...]:
    checks = [
        _credential_store_check(),
        _bitwarden_cli_check(),
        _bitwarden_session_check(),
        _gui_dependency_check(),
        _playwright_check(),
        ReadinessCheck(
            "NordPass sync",
            "manual_required",
            "NordPass personal vault sync uses its supported CSV import/export workflow; no public personal-vault CRUD API is required.",
        ),
        ReadinessCheck(
            "Free password exposure check",
            "ready",
            "HIBP Pwned Passwords range checks are free and k-anonymous; no HIBP API key is required.",
        ),
        _hibp_paid_check(hibp_secret_name),
        ReadinessCheck(
            "macOS app signing",
            "paid_optional",
            "Apple Developer ID signing and notarization require an Apple Developer Program account.",
        ),
        ReadinessCheck(
            "Windows code signing",
            "paid_optional",
            "Windows Authenticode signing requires a code-signing certificate.",
        ),
    ]
    return tuple(checks)


def _credential_store_check() -> ReadinessCheck:
    try:
        import keyring

        keyring.get_keyring()
    except Exception:
        return ReadinessCheck(
            "OS credential store",
            "action_needed",
            "The Python keyring backend is unavailable; secrets cannot be stored safely until the OS credential store works.",
        )
    return ReadinessCheck(
        "OS credential store",
        "ready",
        "Secrets can be stored through macOS Keychain or Windows Credential Manager via keyring.",
    )


def _bitwarden_cli_check() -> ReadinessCheck:
    if shutil.which("bw"):
        return ReadinessCheck("Bitwarden CLI", "ready", "The official bw CLI is installed.")
    return ReadinessCheck(
        "Bitwarden CLI",
        "action_needed",
        "Install the free official Bitwarden CLI before automated Bitwarden writes.",
    )


def _bitwarden_session_check() -> ReadinessCheck:
    if os.environ.get("BW_SESSION"):
        return ReadinessCheck("Bitwarden session", "ready", "BW_SESSION is set for this shell.")
    return ReadinessCheck(
        "Bitwarden session",
        "action_needed",
        "Unlock Bitwarden with bw unlock --raw and set BW_SESSION before vault writes.",
    )


def _gui_dependency_check() -> ReadinessCheck:
    try:
        import PySide6  # noqa: F401
    except Exception:
        return ReadinessCheck(
            "Desktop GUI",
            "action_needed",
            "Install the free GUI dependency with python -m pip install '.[gui]'.",
        )
    return ReadinessCheck("Desktop GUI", "ready", "PySide6 is available.")


def _playwright_check() -> ReadinessCheck:
    try:
        import playwright  # noqa: F401
    except Exception:
        return ReadinessCheck(
            "Reset browser helper",
            "action_needed",
            "Install the free browser helper with python -m pip install playwright && python -m playwright install chromium.",
        )
    return ReadinessCheck("Reset browser helper", "ready", "Playwright is available for opening reset links.")


def _hibp_paid_check(hibp_secret_name: str | None) -> ReadinessCheck:
    if not hibp_secret_name:
        return ReadinessCheck(
            "HIBP email-breach lookup",
            "paid_optional",
            "Skipped. Email-breach lookup requires a HIBP API key; the free password check still works without it.",
        )
    has_secret = bool(_get_secret_if_available(hibp_secret_name))
    if has_secret:
        return ReadinessCheck(
            "HIBP email-breach lookup",
            "ready",
            "A HIBP API key secret is configured for optional email-breach lookup.",
        )
    return ReadinessCheck(
        "HIBP email-breach lookup",
        "paid_optional",
        f"Secret '{hibp_secret_name}' was not found. Add it only if you choose to use paid HIBP email-breach lookup.",
    )


def _get_secret_if_available(secret_name: str) -> str | None:
    try:
        from .secure_store import get_secret

        return get_secret(secret_name)
    except Exception:
        return None
