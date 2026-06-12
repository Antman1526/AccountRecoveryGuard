from __future__ import annotations

from .models import DriftReport, VaultEntry


def compare_vault_entries(bitwarden: VaultEntry, nordpass: VaultEntry) -> DriftReport:
    differences: list[str] = []
    if bitwarden.service_name != nordpass.service_name:
        differences.append("service_name")
    if bitwarden.username != nordpass.username:
        differences.append("username")
    if normalize_url(bitwarden.url) != normalize_url(nordpass.url):
        differences.append("url")
    if bitwarden.password_fingerprint != nordpass.password_fingerprint:
        differences.append("password_fingerprint")
    return DriftReport(
        service_name=bitwarden.service_name,
        username=bitwarden.username,
        in_sync=not differences,
        differences=differences,
    )


def normalize_url(value: str | None) -> str | None:
    if not value:
        return None
    return value.rstrip("/").lower()
