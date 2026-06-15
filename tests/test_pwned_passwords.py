import hashlib

from account_recovery_guard.breach_checker import HibpBreachChecker, parse_pwned_password_suffixes


def test_parse_pwned_password_suffixes_returns_matching_count():
    suffix = "ABCDEF1234567890ABCDEF1234567890ABC"
    payload = f"{suffix}:42\r\nOTHER:1\r\n".encode()

    assert parse_pwned_password_suffixes(payload, suffix) == 42
    assert parse_pwned_password_suffixes(payload, "NOTFOUND") == 0


def test_pwned_password_count_does_not_require_api_key(monkeypatch):
    password = "correct horse battery staple"
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    suffix = digest[5:]

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return f"{suffix}:7\r\n".encode()

    def fake_open(request, timeout):
        assert request.full_url.endswith(digest[:5])
        assert "hibp-api-key" not in dict(request.header_items())
        return FakeResponse()

    monkeypatch.setattr("account_recovery_guard.breach_checker.urlopen", fake_open)

    assert HibpBreachChecker().pwned_password_count(password) == 7
