import json

from account_recovery_guard.audit import AuditLogger, redact_string


def test_audit_logger_redacts_sensitive_fields(tmp_path):
    path = tmp_path / "audit.jsonl"

    AuditLogger(path).write("vault_write", service="Example", password="secret", nested={"token": "abc"})

    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["password"] == "[REDACTED]"
    assert record["nested"]["token"] == "[REDACTED]"
    assert record["service"] == "Example"


def test_audit_logger_redacts_email_and_username_fields(tmp_path):
    path = tmp_path / "audit.jsonl"

    AuditLogger(path).write(
        "email_scan",
        host="imap.example.com",
        username="person@example.com",
        email_address="backup@example.net",
        nested={"mailbox": "Inbox for person@example.com"},
        service="Dropbox",
    )

    record = json.loads(path.read_text(encoding="utf-8"))
    serialized = json.dumps(record)
    assert "person@example.com" not in serialized
    assert "backup@example.net" not in serialized
    assert record["username"] == "[REDACTED]"
    assert record["email_address"] == "[REDACTED]"
    assert record["nested"]["mailbox"] == "[REDACTED]"
    assert record["host"] == "imap.example.com"
    assert record["service"] == "Dropbox"


def test_audit_logger_preserves_non_private_status_fields(tmp_path):
    path = tmp_path / "audit.jsonl"

    AuditLogger(path).write(
        "exposure_plan",
        email_breach_lookup_status="not_run",
        account_count=4,
        contact_email="person@example.com",
    )

    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["email_breach_lookup_status"] == "not_run"
    assert record["account_count"] == 4
    assert record["contact_email"] == "[REDACTED]"
    assert "person@example.com" not in json.dumps(record)


def test_audit_logger_redacts_sensitive_values_inside_safe_named_fields(tmp_path):
    path = tmp_path / "audit.jsonl"

    AuditLogger(path).write(
        "scan_failed",
        detail="Provider returned refresh_token=super-secret access_token=also-secret",
        reset="https://example.com/reset?token=secret-reset-token#continue",
        nested={"message": "Authorization: Bearer ya29.secret-token"},
        services=["Dropbox", "url=https://example.com/reset?token=abc", "owner=person@example.com"],
    )

    record = json.loads(path.read_text(encoding="utf-8"))
    serialized = json.dumps(record)
    assert "super-secret" not in serialized
    assert "also-secret" not in serialized
    assert "secret-reset-token" not in serialized
    assert "ya29.secret-token" not in serialized
    assert "[REDACTED]" in record["detail"]
    assert record["reset"] == "https://example.com/reset?<redacted>#<redacted>"
    assert record["nested"]["message"] == "Authorization: Bearer [REDACTED]"
    assert record["services"][0] == "Dropbox"
    assert record["services"][2] == "owner=[EMAIL_REDACTED]"


def test_redact_string_preserves_urls_without_parameters():
    assert redact_string("Open https://example.com/account/settings") == "Open https://example.com/account/settings"
