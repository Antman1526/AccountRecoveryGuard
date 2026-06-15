import stat

from account_recovery_guard.models import PasswordCandidate
from account_recovery_guard.vaults import NordPassImportVault


def test_nordpass_import_csv_and_parent_directory_are_private(tmp_path):
    candidate = PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Secret123!", "note")
    destination = tmp_path / "nested" / "nordpass-import.csv"

    result = NordPassImportVault().stage_import([candidate], destination)

    assert result == destination
    assert destination.exists()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700


def test_nordpass_import_csv_contains_expected_row_without_extra_echo(tmp_path):
    candidate = PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Secret123!", "note")
    destination = tmp_path / "nordpass-import.csv"

    NordPassImportVault().stage_import([candidate], destination)

    content = destination.read_text(encoding="utf-8")
    assert "Dropbox" in content
    assert "me@example.com" in content
    assert "Secret123!" in content
    assert "Account Recovery Guard" in content
