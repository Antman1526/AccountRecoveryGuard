from account_recovery_guard.models import VaultEntry
from account_recovery_guard.sync import compare_vault_entries


def test_compare_vault_entries_reports_matching_entries():
    bitwarden = VaultEntry(
        service_name="Example",
        username="me@example.com",
        url="https://example.com",
        password_fingerprint="sha256:abc",
    )
    nordpass = VaultEntry(
        service_name="Example",
        username="me@example.com",
        url="https://example.com",
        password_fingerprint="sha256:abc",
    )

    drift = compare_vault_entries(bitwarden, nordpass)

    assert drift.in_sync is True
    assert drift.differences == []


def test_compare_vault_entries_flags_password_drift_without_revealing_secret():
    bitwarden = VaultEntry(
        service_name="Example",
        username="me@example.com",
        url="https://example.com",
        password_fingerprint="sha256:abc",
    )
    nordpass = VaultEntry(
        service_name="Example",
        username="me@example.com",
        url="https://example.com",
        password_fingerprint="sha256:def",
    )

    drift = compare_vault_entries(bitwarden, nordpass)

    assert drift.in_sync is False
    assert drift.differences == ["password_fingerprint"]
