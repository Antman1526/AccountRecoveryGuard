from __future__ import annotations

import re
from dataclasses import dataclass
from email.message import Message
from typing import Protocol

from .account_discovery import AccountDiscovery
from .email_scanner import EmailClassifier
from .gui_state import AccountReview, MailProviderChoice, RotationSession, ScanSummary, VaultSyncStatus
from .models import PasswordCandidate
from .rotation import build_rotation_choices
from .vaults import BitwardenVault, NordPassImportVault, VaultError


class MailProvider(Protocol):
    def fetch_messages(self, days_back: int = 30) -> list[Message]:
        ...


SAFE_SCAN_FAILURE_MESSAGE = "The scan could not finish. Check your provider setup and try again."


@dataclass(frozen=True)
class ProviderSetupCopy:
    title: str
    description: str
    advanced: bool
    technical_details: str = ""


@dataclass(frozen=True)
class GuiVaultWriteResult:
    status: VaultSyncStatus
    user_message: str
    technical_details: str = ""


def describe_provider_setup(provider: MailProviderChoice) -> ProviderSetupCopy:
    if provider == MailProviderChoice.GMAIL:
        return ProviderSetupCopy(
            title="Continue with Gmail",
            description="Connect Gmail so Account Recovery Guard can scan account and security emails.",
            advanced=False,
        )
    if provider == MailProviderChoice.OUTLOOK:
        return ProviderSetupCopy(
            title="Continue with Outlook",
            description="Connect Outlook so Account Recovery Guard can scan account and security emails.",
            advanced=False,
        )
    return ProviderSetupCopy(
        title="Other email",
        description="Use this when your mailbox is not Gmail or Outlook.",
        advanced=True,
        technical_details="Advanced setup uses IMAP host, username, and an app password stored in the OS credential store.",
    )


class GuiScanService:
    def __init__(
        self,
        provider: MailProvider,
        classifier: EmailClassifier | None = None,
        discovery: AccountDiscovery | None = None,
    ) -> None:
        self.provider = provider
        self.classifier = classifier or EmailClassifier()
        self.discovery = discovery or AccountDiscovery()

    def scan(self, days_back: int = 30) -> ScanSummary:
        messages = self.provider.fetch_messages(days_back=days_back)
        findings = [finding for message in messages if (finding := self.classifier.classify(message))]
        accounts = self.discovery.discover(messages)
        discovered_services = {account.service_name.casefold() for account in accounts if account.service_name}
        risky_services = {finding.service_name.casefold() for finding in findings if finding.service_name}
        discovered_count = len(discovered_services | risky_services)
        return ScanSummary.from_findings(findings, discovered_count=discovered_count)


def scan_progress_stages() -> list[str]:
    return [
        "Connecting to mailbox",
        "Reading recent account and security messages",
        "Finding websites tied to this email",
        "Looking for risk signals",
        "Preparing recommendations",
    ]


class GuiRotationService:
    def start(self, service_name: str, username: str, url: str | None = None) -> RotationSession:
        account = AccountReview.from_finding_stub(service_name, username)
        return RotationSession(account=account, choices=build_rotation_choices(service_name, username, url))


class GuiVaultService:
    def __init__(
        self,
        bitwarden: BitwardenVault | None = None,
        nordpass: NordPassImportVault | None = None,
    ) -> None:
        self.bitwarden = bitwarden
        self.nordpass = nordpass or NordPassImportVault()

    def describe_preflight(self) -> VaultSyncStatus:
        if self.bitwarden is None:
            return VaultSyncStatus(bitwarden="not_configured", nordpass="import_needed", verification="pending")
        return VaultSyncStatus(bitwarden="connected", nordpass="import_needed", verification="pending")

    def write_bitwarden(self, candidate: PasswordCandidate) -> GuiVaultWriteResult:
        if self.bitwarden is None:
            return GuiVaultWriteResult(
                status=VaultSyncStatus(bitwarden="not_configured", nordpass="import_needed", verification="pending"),
                user_message="Bitwarden is not configured yet. Connect Bitwarden before writing this login.",
            )
        try:
            self.bitwarden.upsert_login(candidate)
        except VaultError as exc:
            details = _sanitize_vault_message(str(exc))
            guidance = _user_vault_guidance(details)
            return GuiVaultWriteResult(
                status=VaultSyncStatus(bitwarden="verification_failed", nordpass="import_needed", verification="pending"),
                user_message=f"Bitwarden update could not be verified: {guidance}",
                technical_details=details,
            )
        return GuiVaultWriteResult(
            status=VaultSyncStatus(bitwarden="updated", nordpass="import_needed", verification="pending"),
            user_message="Bitwarden was updated. NordPass import is still needed.",
        )


_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\b(token|secret|password|session|api[_-]?key|access[_-]?token|refresh[_-]?token)=\S+"),
    re.compile(r"(?i)\b(refresh-token|access-token|client[_-]secret)=\S+"),
    re.compile(r"(?i)\b(bw_session)=\S+"),
)

_SECRET_COLON_PATTERNS = (
    re.compile(
        r"(?i)(['\"]?\b(?:token|secret|password|session|api[_-]?key|access[_-]?token|"
        r"refresh[_-]?token|client[_-]secret)\b['\"]?\s*:\s*)['\"][^'\"]+['\"]"
    ),
)


def _sanitize_vault_message(message: str) -> str:
    return _sanitize_secret_message(message)


def _sanitize_secret_message(message: str) -> str:
    sanitized = message.strip()
    for pattern in _SECRET_VALUE_PATTERNS:
        sanitized = pattern.sub(lambda match: f"{match.group(1)}=<redacted>", sanitized)
    for pattern in _SECRET_COLON_PATTERNS:
        sanitized = pattern.sub(lambda match: f"{match.group(1)}<redacted>", sanitized)
    return sanitized


def _user_vault_guidance(details: str) -> str:
    first_sentence = details.split(".", 1)[0].strip()
    if first_sentence:
        return first_sentence + "."
    return "Check your Bitwarden CLI session and try again."
