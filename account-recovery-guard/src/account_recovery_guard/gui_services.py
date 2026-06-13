from __future__ import annotations

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


@dataclass(frozen=True)
class ProviderSetupCopy:
    title: str
    description: str
    advanced: bool
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
        discovered_count = max(len(accounts), len(findings))
        return ScanSummary.from_findings(findings, discovered_count=discovered_count)


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

    def write_bitwarden(self, candidate: PasswordCandidate) -> VaultSyncStatus:
        if self.bitwarden is None:
            return VaultSyncStatus(bitwarden="not_configured", nordpass="import_needed", verification="pending")
        try:
            self.bitwarden.upsert_login(candidate)
        except VaultError:
            return VaultSyncStatus(bitwarden="verification_failed", nordpass="import_needed", verification="pending")
        return VaultSyncStatus(bitwarden="updated", nordpass="import_needed", verification="pending")
