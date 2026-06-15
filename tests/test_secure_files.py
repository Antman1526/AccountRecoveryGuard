from account_recovery_guard.secure_files import (
    csv_expiration_warning,
    default_nordpass_import_csv_path,
    secure_delete_file,
    staged_nordpass_csv_warning,
)


def test_csv_expiration_warning_flags_old_plaintext_export():
    assert csv_expiration_warning(age_seconds=600, ttl_seconds=300) is not None
    assert csv_expiration_warning(age_seconds=60, ttl_seconds=300) is None


def test_secure_delete_file_removes_file(tmp_path):
    path = tmp_path / "secret.csv"
    path.write_text("plaintext", encoding="utf-8")

    assert secure_delete_file(path) is True
    assert not path.exists()


def test_secure_delete_file_reports_unlink_failure(tmp_path, monkeypatch):
    path = tmp_path / "secret.csv"
    path.write_text("plaintext", encoding="utf-8")

    def fail_unlink(self):
        raise PermissionError("locked")

    monkeypatch.setattr(type(path), "unlink", fail_unlink)

    assert secure_delete_file(path) is False
    assert path.exists()


def test_staged_nordpass_csv_warning_checks_app_data_path(tmp_path, monkeypatch):
    monkeypatch.setattr("account_recovery_guard.secure_files.user_state_dir", lambda app_name: tmp_path / app_name)
    path = default_nordpass_import_csv_path("account-recovery-guard")
    path.parent.mkdir(parents=True)
    path.write_text("plaintext", encoding="utf-8")

    result = staged_nordpass_csv_warning(ttl_seconds=0, app_name="account-recovery-guard")

    assert result is not None
    found_path, warning = result
    assert found_path == path
    assert "Plaintext CSV" in warning
