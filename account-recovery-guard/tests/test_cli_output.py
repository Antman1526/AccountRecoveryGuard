from __future__ import annotations

import json
from datetime import UTC, datetime

from account_recovery_guard.cli import _print_findings, _redact_url_for_display
from account_recovery_guard.models import CompromisedAccountFinding


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
