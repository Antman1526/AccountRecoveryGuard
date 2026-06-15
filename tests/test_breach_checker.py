import json
from urllib.error import HTTPError

from account_recovery_guard.breach_checker import HibpBreach, HibpBreachChecker, parse_hibp_breaches


def test_parse_hibp_breaches_accepts_truncated_response():
    breaches = parse_hibp_breaches(json.dumps([{"Name": "Adobe"}, {"Name": "Dropbox"}]).encode())

    assert breaches == [HibpBreach(name="Adobe"), HibpBreach(name="Dropbox")]


def test_breach_checker_treats_404_as_no_breach(monkeypatch):
    def fake_open(request, timeout):
        raise HTTPError(request.full_url, 404, "not found", hdrs=None, fp=None)

    monkeypatch.setattr("account_recovery_guard.breach_checker.urlopen", fake_open)

    assert HibpBreachChecker("api-key").breaches_for_account("me@example.com") == []


def test_breach_lookup_requires_api_key():
    try:
        HibpBreachChecker().breaches_for_account("me@example.com")
    except ValueError as exc:
        assert "API key" in str(exc)
    else:
        raise AssertionError("breach lookup without API key should fail closed")
