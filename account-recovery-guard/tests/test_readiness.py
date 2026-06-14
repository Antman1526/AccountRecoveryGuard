from account_recovery_guard.readiness import build_readiness_checks


def test_readiness_includes_free_and_paid_optional_boundaries():
    checks = build_readiness_checks()
    by_name = {check.name: check for check in checks}

    assert by_name["Free password exposure check"].status == "ready"
    assert "no HIBP API key" in by_name["Free password exposure check"].detail
    assert by_name["HIBP email-breach lookup"].status == "paid_optional"
    assert by_name["macOS app signing"].status == "paid_optional"
    assert by_name["Windows code signing"].status == "paid_optional"


def test_readiness_does_not_expose_hibp_secret_value(monkeypatch):
    monkeypatch.setattr("account_recovery_guard.readiness._get_secret_if_available", lambda name: "super-secret-key")

    checks = build_readiness_checks("hibp-api-key")
    hibp = next(check for check in checks if check.name == "HIBP email-breach lookup")

    assert hibp.status == "ready"
    assert "super-secret-key" not in hibp.detail
