from __future__ import annotations

from .models import DriftReport, VaultDashboardRow, VaultEntry


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


def build_vault_dashboard(bitwarden_entries: list[VaultEntry], nordpass_entries: list[VaultEntry]) -> list[VaultDashboardRow]:
    bitwarden = {_entry_key(entry): entry for entry in bitwarden_entries}
    nordpass = {_entry_key(entry): entry for entry in nordpass_entries}
    rows: list[VaultDashboardRow] = []
    for key in sorted(set(bitwarden) | set(nordpass)):
        bw_entry = bitwarden.get(key)
        np_entry = nordpass.get(key)
        if bw_entry and np_entry:
            drift = compare_vault_entries(bw_entry, np_entry)
            rows.append(
                VaultDashboardRow(
                    service_name=bw_entry.service_name,
                    username=bw_entry.username,
                    status="in_sync" if drift.in_sync else "drift",
                    differences=drift.differences,
                )
            )
        elif bw_entry:
            rows.append(VaultDashboardRow(bw_entry.service_name, bw_entry.username, "bitwarden_only", []))
        elif np_entry:
            rows.append(VaultDashboardRow(np_entry.service_name, np_entry.username, "nordpass_only", []))
    return rows


def _entry_key(entry: VaultEntry) -> tuple[str, str]:
    return (entry.service_name.lower(), entry.username.lower())
