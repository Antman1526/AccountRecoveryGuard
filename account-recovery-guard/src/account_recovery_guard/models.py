from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class CompromisedAccountFinding:
    service_name: str
    sender_domain: str
    sender: str
    subject: str
    timestamp: datetime | None
    severity: Severity
    reasons: list[str] = field(default_factory=list)
    reset_link: str | None = None
    message_id: str | None = None


@dataclass(frozen=True)
class PasswordCandidate:
    service_name: str
    username: str
    url: str | None
    password: str
    note: str = ""


@dataclass(frozen=True)
class VaultEntry:
    service_name: str
    username: str
    url: str | None
    password_fingerprint: str


@dataclass(frozen=True)
class DriftReport:
    service_name: str
    username: str
    in_sync: bool
    differences: list[str]


@dataclass(frozen=True)
class ResetWorkflow:
    service_name: str
    reset_link: str | None
    steps: list[str]
    automation_available: bool


@dataclass(frozen=True)
class DiscoveredAccount:
    service_name: str
    sender_domain: str
    message_count: int
    confidence: Literal["low", "medium", "high"]
    reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AccountRisk:
    email_address: str
    service_name: str
    sender_domain: str
    compromised: bool
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    breach_names: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RotationChoiceSummary:
    index: int
    display: str
    length: int
    has_uppercase: bool
    has_lowercase: bool
    has_digit: bool
    has_symbol: bool


@dataclass(frozen=True)
class VaultDashboardRow:
    service_name: str
    username: str
    status: Literal["in_sync", "drift", "bitwarden_only", "nordpass_only"]
    differences: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class VaultPreflight:
    bitwarden_cli_found: bool
    bitwarden_session_present: bool
    nordpass_export_present: bool | None = None


@dataclass(frozen=True)
class VaultPreflightSummary:
    ready: bool
    blockers: list[str] = field(default_factory=list)
