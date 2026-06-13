from account_recovery_guard.secure_files import csv_expiration_warning


def test_csv_expiration_warning_flags_old_plaintext_export():
    assert csv_expiration_warning(age_seconds=600, ttl_seconds=300) is not None
    assert csv_expiration_warning(age_seconds=60, ttl_seconds=300) is None
