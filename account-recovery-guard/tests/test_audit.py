import json

from account_recovery_guard.audit import AuditLogger


def test_audit_logger_redacts_sensitive_fields(tmp_path):
    path = tmp_path / "audit.jsonl"

    AuditLogger(path).write("vault_write", service="Example", password="secret", nested={"token": "abc"})

    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["password"] == "[REDACTED]"
    assert record["nested"]["token"] == "[REDACTED]"
    assert record["service"] == "Example"
