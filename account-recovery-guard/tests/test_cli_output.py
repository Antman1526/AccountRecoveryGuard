from __future__ import annotations

import argparse
import io
import json
import os
import time
from datetime import UTC, datetime

import pytest

from account_recovery_guard import cli
from account_recovery_guard.breach_checker import HibpBreach
from account_recovery_guard.cli import (
    _breach_check,
    _csv_status,
    _exposure_plan,
    _open_reset_link_or_exit,
    _print_findings,
    _redact_url_for_display,
    _secret_value_from_args,
)
from account_recovery_guard.models import CompromisedAccountFinding
from account_recovery_guard.reset_orchestrator import ResetLinkSafetyError


def _finding() -> CompromisedAccountFinding:
    return CompromisedAccountFinding(
        service_name="Example",
        sender_domain="example.com",
        sender="security@example.com",
        subject="Reset your password",
        timestamp=datetime(2026, 6, 14, tzinfo=UTC),
        severity="high",
        reasons=["password reset"],
        reset_link="https://example.com/reset?token=secret-reset-token#continue",
        message_id="message-1",
    )


def test_human_finding_output_redacts_reset_link_tokens(capsys) -> None:
    _print_findings([_finding()], as_json=False)

    output = capsys.readouterr().out

    assert "secret-reset-token" not in output
    assert "#continue" not in output
    assert "https://example.com/reset?<redacted>#<redacted>" in output


def test_json_finding_output_preserves_reset_link_for_local_workflows(capsys) -> None:
    _print_findings([_finding()], as_json=True)

    data = json.loads(capsys.readouterr().out)

    assert data[0]["reset_link"] == "https://example.com/reset?token=secret-reset-token#continue"


def test_malformed_reset_link_display_is_not_echoed() -> None:
    assert _redact_url_for_display("not-a-url token=secret-reset-token") == "redacted reset link"


def test_secret_value_uses_hidden_prompt_when_value_is_omitted(monkeypatch) -> None:
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "prompt-secret")

    value = _secret_value_from_args(argparse.Namespace(value=None, stdin=False))

    assert value == "prompt-secret"


def test_secret_value_can_read_from_stdin_without_shell_history(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("stdin-secret\n"))

    value = _secret_value_from_args(argparse.Namespace(value=None, stdin=True))

    assert value == "stdin-secret"


def test_secret_value_rejects_ambiguous_sources() -> None:
    with pytest.raises(SystemExit):
        _secret_value_from_args(argparse.Namespace(value="positional-secret", stdin=True))


def test_secret_value_rejects_empty_prompt(monkeypatch) -> None:
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "")

    with pytest.raises(SystemExit):
        _secret_value_from_args(argparse.Namespace(value=None, stdin=False))


def test_exposure_plan_blocks_paid_email_lookup_without_explicit_opt_in() -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret="hibp-api-key",
        allow_paid_email_lookup=False,
        password_secret=None,
        accounts_json=None,
        findings_json=None,
        json=True,
    )

    with pytest.raises(SystemExit) as exc:
        _exposure_plan(args)

    assert "Free-only mode" in str(exc.value)
    assert "paid HIBP email-breach lookup" in str(exc.value)


def test_exposure_plan_free_path_does_not_require_paid_lookup(capsys) -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret=None,
        allow_paid_email_lookup=False,
        password_secret=None,
        accounts_json=None,
        findings_json=None,
        json=True,
    )

    _exposure_plan(args)

    data = json.loads(capsys.readouterr().out)
    assert data["email_breach_lookup_status"] == "not_run"
    assert data["breach_count"] == 0


def test_breach_check_blocks_paid_lookup_without_explicit_opt_in() -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret="hibp-api-key",
        allow_paid_email_lookup=False,
        json=True,
    )

    with pytest.raises(SystemExit) as exc:
        _breach_check(args)

    assert "Free-only mode" in str(exc.value)
    assert "paid HIBP email-breach lookup" in str(exc.value)


def test_breach_check_allows_paid_lookup_after_explicit_opt_in(monkeypatch, capsys) -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret="hibp-api-key",
        allow_paid_email_lookup=True,
        json=True,
    )

    monkeypatch.setattr(cli, "get_secret", lambda name: "paid-api-key")

    class FakeChecker:
        def __init__(self, api_key):
            self.api_key = api_key

        def breaches_for_account(self, email):
            assert self.api_key == "paid-api-key"
            assert email == "me@example.com"
            return [HibpBreach("ExampleBreach")]

    monkeypatch.setattr(cli, "HibpBreachChecker", FakeChecker)

    _breach_check(args)

    data = json.loads(capsys.readouterr().out)
    assert data["breaches"] == [{"name": "ExampleBreach"}]


def test_open_reset_link_or_exit_hides_low_level_safety_error(monkeypatch) -> None:
    def raise_safety_error(reset_link, expected_domain_or_url):
        raise ResetLinkSafetyError("embedded credentials")

    monkeypatch.setattr(cli, "open_reset_link", raise_safety_error)

    with pytest.raises(SystemExit) as exc:
        _open_reset_link_or_exit("https://example.com@evil.test/reset", "example.com")

    assert "Reset link was not opened" in str(exc.value)
    assert "official site or app" in str(exc.value)


def test_csv_status_defaults_to_staged_nordpass_path(tmp_path, monkeypatch, capsys) -> None:
    staged = tmp_path / "nordpass-import.csv"
    staged.write_text("plaintext", encoding="utf-8")
    old_timestamp = time.time() - 600
    os.utime(staged, (old_timestamp, old_timestamp))
    monkeypatch.setattr(cli, "default_nordpass_import_csv_path", lambda: staged)

    _csv_status(argparse.Namespace(path=None, ttl_seconds=300, delete=False))

    output = capsys.readouterr().out
    assert "Plaintext CSV is older" in output
    assert str(staged) in output


def test_csv_status_can_delete_default_staged_nordpass_path(tmp_path, monkeypatch, capsys) -> None:
    staged = tmp_path / "nordpass-import.csv"
    staged.write_text("plaintext", encoding="utf-8")
    monkeypatch.setattr(cli, "default_nordpass_import_csv_path", lambda: staged)

    _csv_status(argparse.Namespace(path=None, ttl_seconds=300, delete=True))

    assert capsys.readouterr().out.strip() == "Deleted."
    assert not staged.exists()
