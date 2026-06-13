from __future__ import annotations

import re
from dataclasses import dataclass
from email.message import Message
from inspect import signature
from pathlib import Path
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
class UserFacingSetupError:
    user_message: str
    technical_details: str


@dataclass(frozen=True)
class MailProviderSettings:
    provider: MailProviderChoice
    username: str = ""
    days_back: int = 30
    gmail_client_secret_file: str = ""
    graph_tenant_id: str = "common"
    graph_client_id: str = ""
    imap_host: str = ""
    imap_secret_name: str = ""


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


def build_provider_or_error(settings: MailProviderSettings) -> tuple[MailProvider | None, UserFacingSetupError | None]:
    if settings.provider == MailProviderChoice.GMAIL:
        client_secret_file = settings.gmail_client_secret_file.strip()
        client_secret_path = Path(client_secret_file).expanduser()
        if not client_secret_file or not client_secret_path.exists():
            return None, UserFacingSetupError(
                user_message="Choose a Gmail setup file before starting the scan.",
                technical_details="missing client_secret_file",
            )
        from .oauth_mail import GmailApiMailProvider, GmailOAuthConfig

        return GmailApiMailProvider(GmailOAuthConfig(str(client_secret_path))), None

    if settings.provider == MailProviderChoice.OUTLOOK:
        client_id = settings.graph_client_id.strip()
        if not client_id:
            return None, UserFacingSetupError(
                user_message="Complete Outlook setup before starting the scan.",
                technical_details="missing client_id",
            )
        from .oauth_mail import GraphOAuthConfig, MicrosoftGraphMailProvider

        tenant_id = settings.graph_tenant_id.strip() or "common"
        return MicrosoftGraphMailProvider(GraphOAuthConfig(tenant_id, client_id)), None

    imap_host = settings.imap_host.strip()
    username = settings.username.strip()
    secret_name = settings.imap_secret_name.strip()
    missing = []
    if not imap_host:
        missing.append("imap_host")
    if not username:
        missing.append("username")
    if not secret_name:
        missing.append("imap_secret_name")
    if missing:
        return None, UserFacingSetupError(
            user_message="Complete the other email setup before starting the scan.",
            technical_details=f"missing {', '.join(missing)}",
        )

    from .secure_store import get_secret

    password = get_secret(secret_name)
    if not password:
        return None, UserFacingSetupError(
            user_message="The saved mail password was not found. Check the saved secret name and try again.",
            technical_details="missing saved secret value for imap_secret_name",
        )

    from .email_scanner import ImapEmailScanner, ImapMailboxConfig

    return (
        ImapEmailScanner(
            ImapMailboxConfig(
                host=imap_host,
                username=username,
                password=password,
                days_back=max(settings.days_back, 1),
            )
        ),
        None,
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
        fetch_messages = self.provider.fetch_messages
        if "days_back" in signature(fetch_messages).parameters:
            messages = fetch_messages(days_back=days_back)
        else:
            messages = fetch_messages()
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
