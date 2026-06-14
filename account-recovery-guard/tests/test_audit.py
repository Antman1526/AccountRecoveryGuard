import json

from account_recovery_guard.audit import AuditLogger, redact_string


def test_audit_logger_redacts_sensitive_fields(tmp_path):
    path = tmp_path / "audit.jsonl"

    AuditLogger(path).write("vault_write", service="Example", password="secret", nested={"token": "abc"})

    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["password"] == "[REDACTED]"
    assert record["nested"]["token"] == "[REDACTED]"
    assert record["service"] == "Example"


def test_audit_logger_redacts_sensitive_values_inside_safe_named_fields(tmp_path):
    path = tmp_path / "audit.jsonl"

    AuditLogger(path).write(
        "scan_failed",
        detail="Provider returned refresh_token=super-secret access_token=also-secret",
        reset="https://example.com/reset?token=secret-reset-token#continue",
        nested={"message": "Authorization: Bearer ya29.secret-token"},
        services=["Dropbox", "url=https://example.com/reset?token=abc"],
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


def test_redact_string_preserves_urls_without_parameters():
    assert redact_string("Open https://example.com/account/settings") == "Open https://example.com/account/settings"
