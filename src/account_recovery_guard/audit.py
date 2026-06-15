from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path, PurePath, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .paths import user_log_path

SENSITIVE_KEYS = {"password", "token", "secret", "session", "authorization", "cookie"}
PII_FIELD_KEYS = {
    "account_email",
    "email",
    "email_address",
    "mailbox",
    "mailbox_address",
    "mailbox_name",
    "user_email",
    "user_name",
    "username",
}
PATH_FIELD_KEYS = {
    "csv_path",
    "export_path",
    "file_path",
    "import_path",
    "path",
}
SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(password|token|secret|session|authorization|cookie|api[_-]?key|access[_-]?token|refresh[_-]?token)=([^\s&]+)"
)
SENSITIVE_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")


class AuditLogger:
    def __init__(self, path: Path | None = None):
        self.path = path or user_log_path("account-recovery-guard") / "audit.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **fields: Any) -> None:
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event": event,
            **redact(fields),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _redact_named_value(key, item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_string(value)
    return value


def _redact_named_value(key: str, value: Any) -> Any:
    normalized_key = key.lower()
    if any(marker in normalized_key for marker in SENSITIVE_KEYS):
        return "[REDACTED]"
    if _is_pii_field_key(normalized_key):
        return "[REDACTED]"
    if _is_path_field_key(normalized_key):
        return _redact_path_value(value)
    return redact(value)


def _is_pii_field_key(normalized_key: str) -> bool:
    return (
        normalized_key in PII_FIELD_KEYS
        or normalized_key.endswith("_email")
        or normalized_key.endswith("_email_address")
        or normalized_key.endswith("_mailbox")
        or normalized_key.endswith("_username")
    )


def _is_path_field_key(normalized_key: str) -> bool:
    return normalized_key in PATH_FIELD_KEYS or normalized_key.endswith("_path")


def _redact_path_value(value: Any) -> Any:
    if isinstance(value, str):
        redacted = redact_string(value)
        name = _path_name(redacted)
        return f"[PATH_REDACTED]/{name}" if name else "[PATH_REDACTED]"
    if isinstance(value, list):
        return [_redact_path_value(item) for item in value]
    return "[PATH_REDACTED]"


def _path_name(value: str) -> str:
    if "\\" in value:
        return PureWindowsPath(value).name
    return PurePath(value).name


def redact_string(value: str) -> str:
    redacted = URL_PATTERN.sub(_redact_url, value)
    redacted = SENSITIVE_BEARER_PATTERN.sub("Bearer [REDACTED]", redacted)
    redacted = SENSITIVE_ASSIGNMENT_PATTERN.sub(lambda match: f"{match.group(1)}=[REDACTED]", redacted)
    redacted = EMAIL_PATTERN.sub("[EMAIL_REDACTED]", redacted)
    return redacted


def _redact_url(match: re.Match[str]) -> str:
    url = match.group(0)
    parts = urlsplit(url)
    if parts.query or parts.fragment:
        query = "<redacted>" if parts.query else ""
        fragment = "<redacted>" if parts.fragment else ""
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, fragment))
    return url
