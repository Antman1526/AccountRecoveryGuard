from account_recovery_guard.models import VaultEntry
from account_recovery_guard.sync import build_vault_dashboard


def test_build_vault_dashboard_identifies_missing_and_mismatched_entries():
    bitwarden = [
        VaultEntry("Example", "me@example.com", "https://example.com", "sha256:one"),
        VaultEntry("Solo", "me@example.com", "https://solo.com", "sha256:two"),
    ]
    nordpass = [
        VaultEntry("Example", "me@example.com", "https://example.com", "sha256:different"),
    ]

    rows = build_vault_dashboard(bitwarden, nordpass)

    assert rows[0].status == "drift"
    assert rows[0].differences == ["password_fingerprint"]
    assert rows[1].status == "bitwarden_only"
