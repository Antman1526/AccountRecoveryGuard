from account_recovery_guard.secure_files import csv_expiration_warning, secure_delete_file


def test_csv_expiration_warning_flags_old_plaintext_export():
    assert csv_expiration_warning(age_seconds=600, ttl_seconds=300) is not None
    assert csv_expiration_warning(age_seconds=60, ttl_seconds=300) is None


def test_secure_delete_file_removes_file(tmp_path):
    path = tmp_path / "secret.csv"
    path.write_text("plaintext", encoding="utf-8")

    assert secure_delete_file(path) is True
    assert not path.exists()
