from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .paths import user_log_path

SENSITIVE_KEYS = {"password", "token", "secret", "session", "authorization", "cookie"}
SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(password|token|secret|session|authorization|cookie|api[_-]?key|access[_-]?token|refresh[_-]?token)=([^\s&]+)"
)
SENSITIVE_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")


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
            key: "[REDACTED]" if any(marker in key.lower() for marker in SENSITIVE_KEYS) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_string(value)
    return value


def redact_string(value: str) -> str:
    redacted = URL_PATTERN.sub(_redact_url, value)
    redacted = SENSITIVE_BEARER_PATTERN.sub("Bearer [REDACTED]", redacted)
    redacted = SENSITIVE_ASSIGNMENT_PATTERN.sub(lambda match: f"{match.group(1)}=[REDACTED]", redacted)
    return redacted


def _redact_url(match: re.Match[str]) -> str:
    url = match.group(0)
    parts = urlsplit(url)
    if parts.query or parts.fragment:
        query = "<redacted>" if parts.query else ""
        fragment = "<redacted>" if parts.fragment else ""
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, fragment))
    return url
