from account_recovery_guard.breach_checker import parse_pwned_password_suffixes


def test_parse_pwned_password_suffixes_returns_matching_count():
    suffix = "ABCDEF1234567890ABCDEF1234567890ABC"
    payload = f"{suffix}:42\r\nOTHER:1\r\n".encode()

    assert parse_pwned_password_suffixes(payload, suffix) == 42
    assert parse_pwned_password_suffixes(payload, "NOTFOUND") == 0
