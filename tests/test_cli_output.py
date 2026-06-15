from __future__ import annotations

import argparse
import io
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from account_recovery_guard import cli
from account_recovery_guard.breach_checker import HibpBreach
from account_recovery_guard.cli import (
    _breach_check,
    _csv_status,
    _discover_imap,
    _exposure_plan,
    _exposure_report_to_dict,
    _open_reset_link_or_exit,
    _print_exposure_report,
    _print_findings,
    _pwned_password,
    _redact_url_for_display,
    _scan_gmail_app_password,
    _scan_imap,
    _secret_value_from_args,
    _write_vaults,
)
from account_recovery_guard.exposure import ExposureReport
from account_recovery_guard.exposure import ExposureRecommendation
from account_recovery_guard.models import AccountRiskFinding, PasswordCandidate
from account_recovery_guard.reset_orchestrator import ResetLinkSafetyError


def test_exposure_plan_help_uses_review_first_language() -> None:
    source = (Path(__file__).parents[1] / "src" / "account_recovery_guard" / "cli.py").read_text(encoding="utf-8")

    assert "Build a scoped review plan from mailbox findings and HIBP checks" in source
    assert "prioritized review and rotation plan" not in source
    assert "prioritized password-rotation plan" not in source


def test_breach_check_help_names_paid_hibp_scope() -> None:
    source = (Path(__file__).parents[1] / "src" / "account_recovery_guard" / "cli.py").read_text(encoding="utf-8")

    assert "Check an email address with the paid HIBP email-breach lookup" in source
    assert 'help="Check an email address against Have I Been Pwned"' not in source


def test_cli_description_names_exposure_risk_scope() -> None:
    source = (Path(__file__).parents[1] / "src" / "account_recovery_guard" / "cli.py").read_text(encoding="utf-8")

    assert 'description="Local account recovery and exposure-risk assistant."' in source
    assert 'description="Local account recovery and password rotation assistant."' not in source


def test_rotate_help_is_review_first() -> None:
    source = (Path(__file__).parents[1] / "src" / "account_recovery_guard" / "cli.py").read_text(encoding="utf-8")

    assert "After review, pick from five passwords, use the official reset flow, then update vaults" in source
    assert "Pick from five passwords, complete reset manually, then update vaults" not in source


def test_rotate_open_help_names_verified_reset_link_boundary() -> None:
    source = (Path(__file__).parents[1] / "src" / "account_recovery_guard" / "cli.py").read_text(encoding="utf-8")

    assert "Open verified reset link in Playwright before vault write; otherwise use the official site or app" in source
    assert "Open reset link in Playwright before vault write" not in source


def test_workflow_open_help_names_verified_reset_link_boundary() -> None:
    source = (Path(__file__).parents[1] / "src" / "account_recovery_guard" / "cli.py").read_text(encoding="utf-8")

    assert "Open verified extracted reset link in Playwright; otherwise use the official site or app" in source
    assert "Open extracted reset link in Playwright for manual completion" not in source


def test_passkey_guidance_help_names_official_enrollment_boundary() -> None:
    source = (Path(__file__).parents[1] / "src" / "account_recovery_guard" / "cli.py").read_text(encoding="utf-8")

    assert 'help="Show official passkey enrollment guidance"' in source
    assert 'help="Show safe passkey enrollment guidance"' not in source


def test_vault_live_test_help_names_marked_test_entry_not_safety_claim() -> None:
    source = (Path(__file__).parents[1] / "src" / "account_recovery_guard" / "cli.py").read_text(encoding="utf-8")

    assert 'help="Test Bitwarden write and NordPass import staging with a marked test entry"' in source
    assert 'help="Safely test Bitwarden write and NordPass import staging with a marked test entry"' not in source


def test_exposure_plan_help_names_scoped_review_not_safety_claim() -> None:
    source = (Path(__file__).parents[1] / "src" / "account_recovery_guard" / "cli.py").read_text(encoding="utf-8")

    assert 'help="Build a scoped review plan from mailbox findings and HIBP checks"' in source
    assert "Safely combine mailbox findings and HIBP checks" not in source


def _finding() -> AccountRiskFinding:
    return AccountRiskFinding(
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

    assert "Mailbox risk signals for review" in output
    assert "not proof of account takeover" in output
    assert "Use the official website or app" in output
    assert "secret-reset-token" not in output
    assert "#continue" not in output
    assert "https://example.com/reset?<redacted>#<redacted>" in output


def test_human_finding_output_explains_empty_scan_limits(capsys) -> None:
    _print_findings([], as_json=False)

    output = capsys.readouterr().out

    assert "No mailbox risk signals were found" in output
    assert "does not prove every account is risk-free" in output
    assert "does not prove every account is safe" not in output
    assert "check old reused passwords with HIBP" in output
    assert "whole web" not in output.lower()


def test_json_finding_output_preserves_reset_link_for_local_workflows(capsys) -> None:
    _print_findings([_finding()], as_json=True)

    data = json.loads(capsys.readouterr().out)

    assert data[0]["record_type"] == "account_risk_signal"
    assert data[0]["interpretation"] == "Mailbox risk signal for review; not proof of account takeover."
    assert data[0]["reset_link"] == "https://example.com/reset?token=secret-reset-token#continue"


def test_enriched_json_finding_still_loads_for_local_workflows(tmp_path, capsys) -> None:
    _print_findings([_finding()], as_json=True)
    path = tmp_path / "findings.json"
    path.write_text(capsys.readouterr().out, encoding="utf-8")

    findings = cli._load_findings(path)

    assert len(findings) == 1
    assert isinstance(findings[0], AccountRiskFinding)
    assert findings[0].service_name == "Example"
    assert findings[0].reset_link == "https://example.com/reset?token=secret-reset-token#continue"


def test_malformed_reset_link_display_is_not_echoed() -> None:
    assert _redact_url_for_display("not-a-url token=secret-reset-token") == "redacted reset link"


def test_reset_link_display_redacts_embedded_credentials() -> None:
    display = _redact_url_for_display("https://user:secret-password@example.com/reset?token=abc")

    assert "user" not in display
    assert "secret-password" not in display
    assert display == "https://example.com/reset?<redacted>"


def test_secret_value_uses_hidden_prompt_when_value_is_omitted(monkeypatch) -> None:
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "prompt-secret")

    value = _secret_value_from_args(argparse.Namespace(value=None, stdin=False, allow_shell_history_secret=False))

    assert value == "prompt-secret"


def test_secret_value_can_read_from_stdin_without_shell_history(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("stdin-secret\n"))

    value = _secret_value_from_args(argparse.Namespace(value=None, stdin=True, allow_shell_history_secret=False))

    assert value == "stdin-secret"


def test_secret_value_rejects_ambiguous_sources() -> None:
    with pytest.raises(SystemExit):
        _secret_value_from_args(
            argparse.Namespace(value="positional-secret", stdin=True, allow_shell_history_secret=True)
        )


def test_secret_value_rejects_positional_secret_without_shell_history_opt_in() -> None:
    with pytest.raises(SystemExit) as exc:
        _secret_value_from_args(
            argparse.Namespace(value="positional-secret", stdin=False, allow_shell_history_secret=False)
        )

    assert "shell history" in str(exc.value)


def test_secret_value_allows_positional_secret_with_explicit_shell_history_opt_in() -> None:
    value = _secret_value_from_args(
        argparse.Namespace(value="positional-secret", stdin=False, allow_shell_history_secret=True)
    )

    assert value == "positional-secret"


def test_secret_value_rejects_empty_prompt(monkeypatch) -> None:
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "")

    with pytest.raises(SystemExit):
        _secret_value_from_args(argparse.Namespace(value=None, stdin=False, allow_shell_history_secret=False))


def test_secret_command_success_does_not_echo_secret_name(monkeypatch, capsys) -> None:
    stored = {}

    def fake_set_secret(name, value):
        stored["name"] = name
        stored["value"] = value

    monkeypatch.setattr(cli.sys, "argv", ["arg", "secret", "pasted-name@example.com", "secret-value", "--allow-shell-history-secret"])
    monkeypatch.setattr(cli, "_set_secret", fake_set_secret)

    cli.main()

    output = capsys.readouterr().out
    assert stored == {"name": "pasted-name@example.com", "value": "secret-value"}
    assert "Stored secret in the OS credential store." in output
    assert "pasted-name@example.com" not in output
    assert "secret-value" not in output


def test_secret_delete_command_does_not_echo_secret_name(monkeypatch, capsys) -> None:
    deleted = {}

    def fake_delete_secret(name):
        deleted["name"] = name

    monkeypatch.setattr(cli.sys, "argv", ["arg", "secret-delete", "old-reused-password-for-me@example.com"])
    monkeypatch.setattr(cli, "_delete_secret", fake_delete_secret)

    cli.main()

    output = capsys.readouterr().out
    assert deleted == {"name": "old-reused-password-for-me@example.com"}
    assert "Deleted secret from the OS credential store if it existed." in output
    assert "old-reused-password-for-me@example.com" not in output
    assert "me@example.com" not in output


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


def test_scan_imap_missing_secret_does_not_echo_secret_name(monkeypatch) -> None:
    args = argparse.Namespace(
        host="imap.example.com",
        username="me@example.com",
        secret_name="gmail-app-password-me@example.com",
        days=7,
        folder="INBOX",
        json=False,
    )

    monkeypatch.setattr(cli, "get_secret", lambda name: None)

    with pytest.raises(SystemExit) as exc:
        _scan_imap(args)

    message = str(exc.value)
    assert "IMAP secret was not found" in message
    assert "Store it with: arg secret <secret-name>" in message
    assert "gmail-app-password-me@example.com" not in message
    assert "me@example.com" not in message


def test_discover_imap_missing_secret_does_not_echo_secret_name(monkeypatch) -> None:
    args = argparse.Namespace(
        host="imap.example.com",
        username="me@example.com",
        secret_name="pasted-secret-value-example",
        days=7,
        folder="INBOX",
        json=False,
    )

    monkeypatch.setattr(cli, "get_secret", lambda name: None)

    with pytest.raises(SystemExit) as exc:
        _discover_imap(args)

    message = str(exc.value)
    assert "IMAP secret was not found" in message
    assert "pasted-secret-value-example" not in message


def test_gmail_app_password_missing_secret_does_not_echo_secret_name(monkeypatch) -> None:
    args = argparse.Namespace(
        username="me@example.com",
        secret_name="abcd efgh ijkl mnop",
        days=7,
        recent_inbox=True,
        json=False,
    )

    monkeypatch.setattr(cli, "get_secret", lambda name: None)

    with pytest.raises(SystemExit) as exc:
        _scan_gmail_app_password(args)

    message = str(exc.value)
    assert "Gmail app-password secret was not found" in message
    assert "arg secret <secret-name>" in message
    assert "abcd efgh ijkl mnop" not in message


def test_breach_check_missing_secret_does_not_echo_secret_name(monkeypatch) -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret="hibp-key-for-me@example.com",
        allow_paid_email_lookup=True,
        json=False,
    )

    monkeypatch.setattr(cli, "get_secret", lambda name: None)

    with pytest.raises(SystemExit) as exc:
        _breach_check(args)

    message = str(exc.value)
    assert "HIBP API key secret was not found" in message
    assert "hibp-key-for-me@example.com" not in message
    assert "me@example.com" not in message


def test_pwned_password_missing_secret_does_not_echo_secret_name(monkeypatch) -> None:
    args = argparse.Namespace(password_secret="CorrectHorseBatteryStaple!2", confirm_old_or_reused=True)

    monkeypatch.setattr(cli, "get_secret", lambda name: None)

    with pytest.raises(SystemExit) as exc:
        _pwned_password(args)

    message = str(exc.value)
    assert "Password secret was not found" in message
    assert "CorrectHorseBatteryStaple!2" not in message


def test_pwned_password_requires_old_reused_confirmation_before_secret_lookup(monkeypatch) -> None:
    args = argparse.Namespace(password_secret="old-password", confirm_old_or_reused=False)

    def fail_get_secret(name):
        raise AssertionError("secret should not be read before old/reused confirmation")

    monkeypatch.setattr(cli, "get_secret", fail_get_secret)

    with pytest.raises(SystemExit) as exc:
        _pwned_password(args)

    message = str(exc.value)
    assert "Confirm this is an old or reused password" in message
    assert "Do not check a new generated password" in message
    assert "old-password" not in message


def test_exposure_plan_missing_secrets_do_not_echo_secret_names(monkeypatch) -> None:
    monkeypatch.setattr(cli, "get_secret", lambda name: None)

    hibp_args = argparse.Namespace(
        email="me@example.com",
        hibp_secret="hibp-key-for-me@example.com",
        allow_paid_email_lookup=True,
        password_secret=None,
        accounts_json=None,
        findings_json=None,
        json=False,
    )
    with pytest.raises(SystemExit) as hibp_exc:
        _exposure_plan(hibp_args)

    hibp_message = str(hibp_exc.value)
    assert "HIBP API key secret was not found" in hibp_message
    assert "hibp-key-for-me@example.com" not in hibp_message

    password_args = argparse.Namespace(
        email="me@example.com",
        hibp_secret=None,
        allow_paid_email_lookup=False,
        password_secret="CorrectHorseBatteryStaple!2",
        confirm_old_or_reused=True,
        accounts_json=None,
        findings_json=None,
        json=False,
    )
    with pytest.raises(SystemExit) as password_exc:
        _exposure_plan(password_args)

    password_message = str(password_exc.value)
    assert "Password secret was not found" in password_message
    assert "CorrectHorseBatteryStaple!2" not in password_message


def test_exposure_plan_requires_old_reused_confirmation_before_password_secret_lookup(monkeypatch) -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret=None,
        allow_paid_email_lookup=False,
        password_secret="old-password",
        confirm_old_or_reused=False,
        accounts_json=None,
        findings_json=None,
        json=False,
    )

    def fail_get_secret(name):
        raise AssertionError("password secret should not be read before old/reused confirmation")

    monkeypatch.setattr(cli, "get_secret", fail_get_secret)

    with pytest.raises(SystemExit) as exc:
        _exposure_plan(args)

    message = str(exc.value)
    assert "Confirm this is an old or reused password" in message
    assert "Do not check a new generated password" in message
    assert "old-password" not in message


def test_exposure_plan_requires_old_reused_confirmation_before_paid_lookup(monkeypatch) -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret="hibp-api-key",
        allow_paid_email_lookup=True,
        password_secret="old-password",
        confirm_old_or_reused=False,
        accounts_json=None,
        findings_json=None,
        json=False,
    )

    def fail_get_secret(name):
        raise AssertionError("HIBP secret should not be read before old/reused password confirmation")

    class FailChecker:
        def __init__(self, api_key=None):
            raise AssertionError("HIBP checker should not be created before old/reused password confirmation")

    monkeypatch.setattr(cli, "get_secret", fail_get_secret)
    monkeypatch.setattr(cli, "HibpBreachChecker", FailChecker)

    with pytest.raises(SystemExit) as exc:
        _exposure_plan(args)

    message = str(exc.value)
    assert "Confirm this is an old or reused password" in message
    assert "Do not check a new generated password" in message
    assert "old-password" not in message
    assert "hibp-api-key" not in message


def test_write_vaults_missing_secret_does_not_echo_secret_name(monkeypatch) -> None:
    args = argparse.Namespace(
        service="Example",
        username="me@example.com",
        url="https://example.com",
        password_secret="CorrectHorseBatteryStaple!2",
        note=None,
        skip_bitwarden=True,
        nordpass_csv="/tmp/nordpass.csv",
    )

    monkeypatch.setattr(cli, "get_secret", lambda name: None)

    with pytest.raises(SystemExit) as exc:
        _write_vaults(args)

    message = str(exc.value)
    assert "New password secret was not found" in message
    assert "CorrectHorseBatteryStaple!2" not in message


def test_breach_check_allows_paid_lookup_after_explicit_opt_in(monkeypatch, capsys) -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret="hibp-api-key",
        allow_paid_email_lookup=True,
        json=True,
    )

    monkeypatch.setattr(cli, "get_secret", lambda name: "paid-api-key")

    class FakeChecker:
        def __init__(self, api_key=None):
            self.api_key = api_key

        def breaches_for_account(self, email):
            assert self.api_key == "paid-api-key"
            assert email == "me@example.com"
            return [HibpBreach("ExampleBreach")]

    monkeypatch.setattr(cli, "HibpBreachChecker", FakeChecker)

    _breach_check(args)

    data = json.loads(capsys.readouterr().out)
    assert data["record_type"] == "hibp_email_breach_lookup"
    assert data["lookup_boundary"] == (
        "Known: HIBP returned breach records for this email. Unknown: private breaches, dark-web dumps, "
        "private forums, and paid breach-intelligence sources may still exist outside HIBP."
    )
    assert data["breaches"] == [{"name": "ExampleBreach"}]


def test_breach_check_json_no_match_keeps_lookup_boundary(monkeypatch, capsys) -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret="hibp-api-key",
        allow_paid_email_lookup=True,
        json=True,
    )

    monkeypatch.setattr(cli, "get_secret", lambda name: "paid-api-key")

    class FakeChecker:
        def __init__(self, api_key=None):
            self.api_key = api_key

        def breaches_for_account(self, email):
            assert self.api_key == "paid-api-key"
            assert email == "me@example.com"
            return []

    monkeypatch.setattr(cli, "HibpBreachChecker", FakeChecker)

    _breach_check(args)

    data = json.loads(capsys.readouterr().out)
    assert data["record_type"] == "hibp_email_breach_lookup"
    assert data["breaches"] == []
    assert "does not prove the email is absent from every breach" in data["lookup_boundary"]
    assert "whole web" not in data["lookup_boundary"].lower()


def test_breach_check_human_no_match_keeps_unknown_private_sources_visible(monkeypatch, capsys) -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret="hibp-api-key",
        allow_paid_email_lookup=True,
        json=False,
    )

    monkeypatch.setattr(cli, "get_secret", lambda name: "paid-api-key")

    class FakeChecker:
        def __init__(self, api_key=None):
            self.api_key = api_key

        def breaches_for_account(self, email):
            assert self.api_key == "paid-api-key"
            assert email == "me@example.com"
            return []

    monkeypatch.setattr(cli, "HibpBreachChecker", FakeChecker)

    _breach_check(args)

    output = capsys.readouterr().out
    assert "No HIBP breaches returned for me@example.com." in output
    assert "does not prove the email is absent from every breach" in output
    assert "private breaches" in output
    assert "paid breach-intelligence sources" in output
    assert "whole web" not in output.lower()


def test_breach_check_human_matches_explain_known_dataset_scope(monkeypatch, capsys) -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret="hibp-api-key",
        allow_paid_email_lookup=True,
        json=False,
    )

    monkeypatch.setattr(cli, "get_secret", lambda name: "paid-api-key")

    class FakeChecker:
        def __init__(self, api_key=None):
            self.api_key = api_key

        def breaches_for_account(self, email):
            assert self.api_key == "paid-api-key"
            assert email == "me@example.com"
            return [HibpBreach("ExampleBreach")]

    monkeypatch.setattr(cli, "HibpBreachChecker", FakeChecker)

    _breach_check(args)

    output = capsys.readouterr().out
    assert "HIBP returned 1 breach(es) for me@example.com:" in output
    assert "Known: HIBP returned breach records for this email." in output
    assert "Unknown: private breaches" in output
    assert "ExampleBreach" in output


def test_breach_check_hides_paid_lookup_failure_details(monkeypatch) -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret="hibp-api-key",
        allow_paid_email_lookup=True,
        json=False,
    )

    monkeypatch.setattr(cli, "get_secret", lambda name: "paid-api-key")

    class FakeChecker:
        def __init__(self, api_key=None):
            self.api_key = api_key

        def breaches_for_account(self, email):
            assert self.api_key == "paid-api-key"
            assert email == "me@example.com"
            raise RuntimeError("hibp failed api_key=paid-api-key token=secret-value")

    monkeypatch.setattr(cli, "HibpBreachChecker", FakeChecker)

    with pytest.raises(SystemExit) as exc:
        _breach_check(args)

    message = str(exc.value)
    assert "HIBP email breach lookup could not finish" in message
    assert "hibp failed" not in message
    assert "paid-api-key" not in message
    assert "secret-value" not in message


def test_exposure_plan_hides_paid_lookup_failure_details(monkeypatch) -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret="hibp-api-key",
        allow_paid_email_lookup=True,
        password_secret=None,
        accounts_json=None,
        findings_json=None,
        json=False,
    )

    monkeypatch.setattr(cli, "get_secret", lambda name: "paid-api-key")

    class FakeChecker:
        def __init__(self, api_key=None):
            self.api_key = api_key

        def breaches_for_account(self, email):
            assert self.api_key == "paid-api-key"
            assert email == "me@example.com"
            raise RuntimeError("hibp failed api_key=paid-api-key token=secret-value")

    monkeypatch.setattr(cli, "HibpBreachChecker", FakeChecker)

    with pytest.raises(SystemExit) as exc:
        _exposure_plan(args)

    message = str(exc.value)
    assert "HIBP email breach lookup could not finish" in message
    assert "hibp failed" not in message
    assert "paid-api-key" not in message
    assert "secret-value" not in message


def test_pwned_password_cli_prints_known_unknown_limits(monkeypatch, capsys) -> None:
    args = argparse.Namespace(password_secret="old-password", confirm_old_or_reused=True)

    class FakeChecker:
        def pwned_password_count(self, password):
            assert password == "hunter2"
            return 12

    class FakeAudit:
        def write(self, event, **kwargs):
            assert event == "hibp_pwned_password_check"
            assert kwargs == {"count": 12}

    monkeypatch.setattr(cli, "get_secret", lambda name: "hunter2")
    monkeypatch.setattr(cli, "HibpBreachChecker", FakeChecker)
    monkeypatch.setattr(cli, "AuditLogger", lambda: FakeAudit())

    _pwned_password(args)

    output = capsys.readouterr().out
    assert "Only check an old or reused password" in output
    assert "Do not check a new generated password" in output
    assert "When finished, delete the temporary password-check secret with: arg secret-delete <secret-name>" in output
    assert "old-password" not in output
    assert "Password appears 12 time(s)" in output
    assert "Do not reuse this password; review where it was used before rotating accounts." in output
    assert "Do not use it." not in output
    assert "Known:" in output
    assert "Unknown:" in output
    assert "does not identify every site" in output
    assert "one at a time" in output
    assert "hunter2" not in output


def test_pwned_password_cli_hides_checker_failure_details(monkeypatch) -> None:
    args = argparse.Namespace(password_secret="old-password", confirm_old_or_reused=True)

    class FakeChecker:
        def pwned_password_count(self, password):
            assert password == "hunter2"
            raise RuntimeError("network failed password=hunter2 token=secret-value")

    monkeypatch.setattr(cli, "get_secret", lambda name: "hunter2")
    monkeypatch.setattr(cli, "HibpBreachChecker", FakeChecker)

    with pytest.raises(SystemExit) as exc:
        _pwned_password(args)

    message = str(exc.value)
    assert "Password exposure check could not finish" in message
    assert "network failed" not in message
    assert "hunter2" not in message
    assert "secret-value" not in message


def test_exposure_plan_hides_password_check_failure_details(monkeypatch) -> None:
    args = argparse.Namespace(
        email="me@example.com",
        hibp_secret=None,
        allow_paid_email_lookup=False,
        password_secret="old-password",
        confirm_old_or_reused=True,
        accounts_json=None,
        findings_json=None,
        json=False,
    )

    class FakeChecker:
        def pwned_password_count(self, password):
            assert password == "hunter2"
            raise RuntimeError("range api failed password=hunter2 token=secret-value")

    monkeypatch.setattr(cli, "get_secret", lambda name: "hunter2")
    monkeypatch.setattr(cli, "HibpBreachChecker", FakeChecker)

    with pytest.raises(SystemExit) as exc:
        _exposure_plan(args)

    message = str(exc.value)
    assert "Password exposure check could not finish" in message
    assert "range api failed" not in message
    assert "hunter2" not in message
    assert "secret-value" not in message


def test_exposure_report_password_check_output_keeps_private_sources_uncertain(capsys) -> None:
    report = ExposureReport(
        email_address="me@example.com",
        breach_count=0,
        email_breach_lookup_status="not_run",
        password_pwned_count=0,
        recommendations=(),
    )

    _print_exposure_report(report)

    output = capsys.readouterr().out
    assert "Exposure review plan for me@example.com" in output
    assert "Safe exposure plan for" not in output
    assert "Password exposure check: not found in HIBP Pwned Passwords" in output
    assert "Only check an old or reused password" in output
    assert "Do not check a new generated password" in output
    assert "When finished, delete the temporary password-check secret with: arg secret-delete <secret-name>" in output
    assert "Known:" in output
    assert "Unknown:" in output
    assert "private breach dumps" in output
    assert "does not prove" not in output.lower()
    assert "hunter2" not in output


def test_exposure_report_password_hit_avoids_blanket_rotation_instruction(capsys) -> None:
    report = ExposureReport(
        email_address="me@example.com",
        breach_count=0,
        email_breach_lookup_status="not_run",
        password_pwned_count=12,
        recommendations=(),
    )

    _print_exposure_report(report)

    output = capsys.readouterr().out
    assert "Password exposure check: found 12 time(s)" in output
    assert "Only check an old or reused password" in output
    assert "Do not check a new generated password" in output
    assert "When finished, delete the temporary password-check secret with: arg secret-delete <secret-name>" in output
    assert "review where you reused it, then rotate only those accounts" in output
    assert "rotate only those reused accounts" not in output
    assert "No services were available to prioritize" in output
    assert "Fallback review steps:" in output
    assert "Safe fallback:" not in output
    assert "Use your password manager or memory to identify where this old password was reused." in output
    assert "Rotate only those accounts, one at a time, starting with email and financial accounts." in output
    assert "Rotate only those reused accounts" not in output
    assert "Do not paste the password into search engines, paste sites, or random breach-check pages." in output
    assert "rotate any account using it" not in output


def test_exposure_report_json_carries_safe_action_metadata() -> None:
    report = ExposureReport(
        email_address="me@example.com",
        breach_count=1,
        email_breach_lookup_status="checked",
        password_pwned_count=12,
        recommendations=(
            ExposureRecommendation(
                service_name="Dropbox",
                sender_domain="dropbox.com",
                priority="high",
                rotate=True,
                reasons=("known breach for this email: Dropbox",),
            ),
            ExposureRecommendation(
                service_name="Bank",
                sender_domain="bank.example",
                priority="high",
                rotate=False,
                reasons=(
                    "checked password appears in HIBP Pwned Passwords; "
                    "confirm this account used that password before rotating",
                ),
            ),
        ),
    )

    data = _exposure_report_to_dict(report)
    by_service = {item["service_name"]: item for item in data["recommendations"]}

    assert data["record_type"] == "exposure_review_plan"
    assert data["record_type"] != "safe_exposure_plan"
    assert "does not search the whole web" in data["interpretation"]
    assert (
        "private breach datasets, dark-web dumps, private forums, or paid intelligence sources "
        "may still exist outside this plan"
    ) in data["interpretation"]
    assert "paid intelligence sources may differ" not in data["interpretation"]
    assert data["password_check_scope_warning"] == (
        "Only check an old or reused password. Do not check a new generated password."
    )
    assert data["password_secret_cleanup_reminder"] == (
        "When finished, delete the temporary password-check secret with: arg secret-delete <secret-name>"
    )
    assert "old-password" not in json.dumps(data)
    assert by_service["Dropbox"]["action"] == "rotate"
    assert by_service["Dropbox"]["action_detail"] == "Rotate this account because a separate risk signal supports rotation."
    assert by_service["Bank"]["action"] == "review_reuse"
    assert by_service["Bank"]["action_detail"] == (
        "Review whether this account used the checked password before rotating it."
    )


def test_exposure_report_json_omits_password_secret_cleanup_when_password_check_not_run() -> None:
    report = ExposureReport(
        email_address="me@example.com",
        breach_count=0,
        email_breach_lookup_status="not_run",
        password_pwned_count=None,
        recommendations=(),
    )

    data = _exposure_report_to_dict(report)

    assert data["password_pwned_count"] is None
    assert data["password_secret_cleanup_reminder"] is None
    assert data["password_check_scope_warning"] == (
        "Only check an old or reused password. Do not check a new generated password."
    )


def test_exposure_report_human_output_prints_safe_action_details(capsys) -> None:
    report = ExposureReport(
        email_address="me@example.com",
        breach_count=1,
        email_breach_lookup_status="checked",
        password_pwned_count=12,
        recommendations=(
            ExposureRecommendation(
                service_name="Dropbox",
                sender_domain="dropbox.com",
                priority="high",
                rotate=True,
                reasons=("known breach for this email: Dropbox",),
            ),
            ExposureRecommendation(
                service_name="Bank",
                sender_domain="bank.example",
                priority="high",
                rotate=False,
                reasons=(
                    "checked password appears in HIBP Pwned Passwords; "
                    "confirm this account used that password before rotating",
                ),
            ),
        ),
    )

    _print_exposure_report(report)

    output = capsys.readouterr().out
    assert "- [high] ROTATE: Dropbox (dropbox.com)" in output
    assert "action: Rotate this account because a separate risk signal supports rotation." in output
    assert "- [high] review reuse: Bank (bank.example)" in output
    assert "action: Review whether this account used the checked password before rotating it." in output
    assert "rotate every account" not in output.lower()


def test_rotate_does_not_print_selected_password_without_explicit_reveal(monkeypatch, capsys, tmp_path) -> None:
    args = argparse.Namespace(
        service="Example",
        username="me@example.com",
        url="https://example.com",
        reset_link=None,
        length=32,
        nordpass_csv=str(tmp_path / "nordpass.csv"),
        skip_bitwarden=True,
        open=False,
        reveal_all=False,
        reveal_selected=False,
        copy_selected=False,
    )
    candidate = PasswordCandidate("Example", "me@example.com", "https://example.com", "PlainSecret123!", "note")

    monkeypatch.setattr(cli, "build_rotation_choices", lambda *args, **kwargs: [candidate])
    monkeypatch.setattr("builtins.input", lambda prompt: "1")

    with pytest.raises(SystemExit) as exc:
        cli._rotate(args)

    output = capsys.readouterr().out
    message = str(exc.value)
    assert "Selected password was not printed" in message
    assert "--copy-selected" in message
    assert "--reveal-selected" in message
    assert "PlainSecret123!" not in output
    assert "PlainSecret123!" not in message


def test_rotate_reveals_selected_password_only_after_explicit_opt_in(monkeypatch, capsys, tmp_path) -> None:
    args = argparse.Namespace(
        service="Example",
        username="me@example.com",
        url="https://example.com",
        reset_link=None,
        length=32,
        nordpass_csv=str(tmp_path / "nordpass.csv"),
        skip_bitwarden=True,
        open=False,
        reveal_all=False,
        reveal_selected=True,
        copy_selected=False,
    )
    candidate = PasswordCandidate("Example", "me@example.com", "https://example.com", "PlainSecret123!", "note")
    prompts = iter(["1", "ROTATED"])

    monkeypatch.setattr(cli, "build_rotation_choices", lambda *args, **kwargs: [candidate])
    monkeypatch.setattr("builtins.input", lambda prompt: next(prompts))

    cli._rotate(args)

    output = capsys.readouterr().out
    assert "Unsafe reveal requested" in output
    assert "Selected password: PlainSecret123!" in output


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


def test_csv_status_reports_delete_failure_for_existing_plaintext_csv(tmp_path, monkeypatch, capsys) -> None:
    staged = tmp_path / "nordpass-import.csv"
    staged.write_text("plaintext", encoding="utf-8")
    monkeypatch.setattr(cli, "default_nordpass_import_csv_path", lambda: staged)
    monkeypatch.setattr(cli, "delete_file", lambda path: False)

    _csv_status(argparse.Namespace(path=None, ttl_seconds=300, delete=True))

    output = capsys.readouterr().out
    assert "Delete failed" in output
    assert str(staged) in output
