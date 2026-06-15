from pathlib import Path
from types import SimpleNamespace
import sys

from account_recovery_guard.readiness import build_readiness_checks
from account_recovery_guard.readiness import _credential_store_check


def test_readiness_includes_free_and_paid_optional_boundaries():
    checks = build_readiness_checks()
    by_name = {check.name: check for check in checks}

    assert by_name["Free password exposure check"].status == "ready"
    assert by_name["Staged NordPass CSV cleanup"].status == "ready"
    assert "no HIBP API key" in by_name["Free password exposure check"].detail
    assert by_name["HIBP email-breach lookup"].status == "paid_optional"
    assert by_name["macOS app signing"].status == "paid_optional"
    assert by_name["Windows code signing"].status == "paid_optional"


def test_ready_credential_store_mentions_temporary_secret_cleanup(monkeypatch):
    monkeypatch.setitem(sys.modules, "keyring", SimpleNamespace(get_keyring=lambda: object()))

    check = _credential_store_check()

    assert check.status == "ready"
    assert "delete temporary password-check secrets" in check.detail


def test_missing_credential_store_names_os_store_not_generic_safety(monkeypatch):
    def unavailable_keyring():
        raise RuntimeError("keyring unavailable")

    monkeypatch.setitem(sys.modules, "keyring", SimpleNamespace(get_keyring=unavailable_keyring))

    check = _credential_store_check()

    assert check.status == "action_needed"
    assert "secrets cannot be stored through the OS credential store until keyring works" in check.detail
    assert "secrets cannot be stored safely until the OS credential store works" not in check.detail


def test_readiness_does_not_expose_hibp_secret_value(monkeypatch):
    monkeypatch.setattr("account_recovery_guard.readiness._get_secret_if_available", lambda name: "super-secret-key")

    checks = build_readiness_checks("hibp-api-key")
    hibp = next(check for check in checks if check.name == "HIBP email-breach lookup")

    assert hibp.status == "ready"
    assert "super-secret-key" not in hibp.detail


def test_readiness_missing_hibp_secret_does_not_echo_secret_name(monkeypatch):
    monkeypatch.setattr("account_recovery_guard.readiness._get_secret_if_available", lambda name: None)

    checks = build_readiness_checks("hibp-key-for-me@example.com")
    hibp = next(check for check in checks if check.name == "HIBP email-breach lookup")

    assert hibp.status == "paid_optional"
    assert "HIBP API key secret was not found" in hibp.detail
    assert "hibp-key-for-me@example.com" not in hibp.detail
    assert "me@example.com" not in hibp.detail


def test_readiness_flags_stale_staged_nordpass_csv(monkeypatch):
    monkeypatch.setattr(
        "account_recovery_guard.readiness.staged_nordpass_csv_warning",
        lambda: (Path("/tmp/nordpass-import.csv"), "Plaintext CSV is older than 300 seconds; import or delete it now."),
    )

    checks = build_readiness_checks()
    cleanup = next(check for check in checks if check.name == "Staged NordPass CSV cleanup")

    assert cleanup.status == "action_needed"
    assert "import or delete" in cleanup.detail
    assert "/tmp/nordpass-import.csv" in cleanup.detail
