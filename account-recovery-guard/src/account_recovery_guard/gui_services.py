from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from email.message import Message
from inspect import signature
from pathlib import Path
from typing import Protocol

from .account_discovery import AccountDiscovery
from .breach_checker import HibpBreachChecker
from .email_scanner import EmailClassifier
from .gui_state import AccountReview, MailProviderChoice, RotationSession, ScanSummary, VaultSyncStatus
from .models import PasswordCandidate
from .rotation import build_rotation_choices
from .vaults import BitwardenVault, NordPassImportVault, VaultError


class MailProvider(Protocol):
    def fetch_messages(self, days_back: int = 30) -> list[Message]:
        ...


DEFAULT_GUI_SCAN_DAYS = 365
SAFE_SCAN_FAILURE_MESSAGE = "The scan could not finish. Check your provider setup and try again."
SETUP_DETAIL_MISSING_CLIENT_SECRET_FILE = "missing_client_secret_file"
SETUP_DETAIL_MISSING_GMAIL_APP_PASSWORD = "missing_gmail_app_password"
SETUP_DETAIL_INVALID_GMAIL_APP_PASSWORD = "invalid_gmail_app_password"
SETUP_DETAIL_MISSING_CLIENT_ID = "missing_client_id"
SETUP_DETAIL_MISSING_IMAP_SETUP = "missing_imap_setup"
SETUP_DETAIL_MISSING_SAVED_IMAP_SECRET = "missing_saved_imap_secret"
SETUP_DETAIL_CREDENTIAL_STORE_UNAVAILABLE = "credential_store_unavailable"
SETUP_DETAIL_MISSING_PROVIDER = "missing_provider"
SETUP_DETAIL_SCAN_CONSENT_REQUIRED = "scan_consent_required"
SETUP_DETAIL_SECOND_PERSON_CONSENT_REQUIRED = "second_person_consent_required"
SETUP_DETAIL_MISSING_PROVIDER_INSTANCE = "missing_provider_instance"
SETUP_DETAIL_SCAN_FAILED = "scan_failed"
FIELD_USERNAME = "username"
FIELD_PERSON_LABEL = "person_label"
FIELD_DAYS_BACK = "days_back"
FIELD_GMAIL_APP_PASSWORD = "gmail_app_password"
FIELD_GMAIL_FULL_MAILBOX = "gmail_full_mailbox"
FIELD_GMAIL_ADVANCED_OAUTH = "gmail_advanced_oauth"
FIELD_GMAIL_CLIENT_SECRET_FILE = "gmail_client_secret_file"
FIELD_GRAPH_TENANT_ID = "graph_tenant_id"
FIELD_GRAPH_CLIENT_ID = "graph_client_id"
FIELD_IMAP_HOST = "imap_host"
FIELD_IMAP_SECRET_NAME = "imap_secret_name"
CONTROLLED_SETUP_DETAIL_CODES = frozenset(
    {
        SETUP_DETAIL_MISSING_CLIENT_SECRET_FILE,
        SETUP_DETAIL_MISSING_GMAIL_APP_PASSWORD,
        SETUP_DETAIL_INVALID_GMAIL_APP_PASSWORD,
        SETUP_DETAIL_MISSING_CLIENT_ID,
        SETUP_DETAIL_MISSING_IMAP_SETUP,
        SETUP_DETAIL_MISSING_SAVED_IMAP_SECRET,
        SETUP_DETAIL_CREDENTIAL_STORE_UNAVAILABLE,
        SETUP_DETAIL_MISSING_PROVIDER,
        SETUP_DETAIL_SCAN_CONSENT_REQUIRED,
        SETUP_DETAIL_SECOND_PERSON_CONSENT_REQUIRED,
        SETUP_DETAIL_MISSING_PROVIDER_INSTANCE,
        SETUP_DETAIL_SCAN_FAILED,
    }
)


@dataclass(frozen=True)
class ProviderSetupCopy:
    title: str
    description: str
    advanced: bool
    technical_details: str = ""


@dataclass(frozen=True)
class ProviderSetupAction:
    label: str
    url: str


@dataclass(frozen=True)
class UserFacingSetupError:
    user_message: str
    technical_details: str


@dataclass(frozen=True)
class MailProviderSettings:
    provider: MailProviderChoice
    username: str = ""
    days_back: int = DEFAULT_GUI_SCAN_DAYS
    gmail_app_password: str = ""
    gmail_secret_name: str = ""
    gmail_full_mailbox: bool = True
    gmail_advanced_oauth: bool = False
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


@dataclass(frozen=True)
class GuiPasswordExposureResult:
    count: int | None
    user_message: str
    rotation_recommended: bool = False
    technical_details: str = ""


def controlled_setup_detail_for_log(technical_details: str) -> str:
    if technical_details in CONTROLLED_SETUP_DETAIL_CODES:
        return technical_details
    return ""


def describe_provider_setup(provider: MailProviderChoice) -> ProviderSetupCopy:
    if provider == MailProviderChoice.GMAIL:
        return ProviderSetupCopy(
            title="Continue with Gmail",
            description="Connect Gmail with a Google app password so Account Recovery Guard can scan account and security emails.",
            advanced=False,
            technical_details="Work or school Gmail may require advanced OAuth setup instead.",
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


def visible_setup_fields(
    provider: MailProviderChoice | None,
    gmail_advanced_oauth: bool = False,
    gmail_full_mailbox: bool = True,
) -> frozenset[str]:
    if provider == MailProviderChoice.GMAIL:
        fields = {
            FIELD_PERSON_LABEL,
            FIELD_USERNAME,
            FIELD_GMAIL_ADVANCED_OAUTH,
        }
        if gmail_advanced_oauth:
            fields.add(FIELD_DAYS_BACK)
            fields.add(FIELD_GMAIL_CLIENT_SECRET_FILE)
        else:
            fields.add(FIELD_GMAIL_APP_PASSWORD)
            fields.add(FIELD_GMAIL_FULL_MAILBOX)
            if not gmail_full_mailbox:
                fields.add(FIELD_DAYS_BACK)
        return frozenset(fields)
    if provider == MailProviderChoice.OUTLOOK:
        return frozenset(
            {
                FIELD_USERNAME,
                FIELD_PERSON_LABEL,
                FIELD_DAYS_BACK,
                FIELD_GRAPH_TENANT_ID,
                FIELD_GRAPH_CLIENT_ID,
            }
        )
    if provider == MailProviderChoice.OTHER_EMAIL:
        return frozenset(
            {
                FIELD_USERNAME,
                FIELD_PERSON_LABEL,
                FIELD_DAYS_BACK,
                FIELD_IMAP_HOST,
                FIELD_IMAP_SECRET_NAME,
            }
        )
    return frozenset({FIELD_PERSON_LABEL, FIELD_USERNAME, FIELD_DAYS_BACK})


def scan_scope_note(
    provider: MailProviderChoice | None,
    days_back: int = DEFAULT_GUI_SCAN_DAYS,
    gmail_full_mailbox: bool = True,
    gmail_advanced_oauth: bool = False,
) -> str:
    bounded_days = max(days_back, 1)
    if provider == MailProviderChoice.GMAIL and gmail_full_mailbox and not gmail_advanced_oauth:
        return (
            "Scope: full Gmail mailbox. The app scans Gmail All Mail, not just recent Inbox messages. "
            "Large mailboxes can take a few minutes."
        )
    if provider == MailProviderChoice.GMAIL and gmail_advanced_oauth:
        return f"Scope: last {bounded_days} day(s) through Gmail OAuth. Increase the days for a broader free scan."
    if provider == MailProviderChoice.GMAIL:
        return f"Scope: last {bounded_days} day(s) of Gmail Inbox. Turn on full mailbox to scan Gmail All Mail."
    if provider == MailProviderChoice.OUTLOOK:
        return f"Scope: last {bounded_days} day(s) through Microsoft Graph. Increase the days for a broader free scan."
    if provider == MailProviderChoice.OTHER_EMAIL:
        return f"Scope: last {bounded_days} day(s) over IMAP. Increase only if your provider handles large scans well."
    return "Choose a provider to see the scan scope before anything starts."


def provider_setup_note(provider: MailProviderChoice | None, gmail_advanced_oauth: bool = False) -> str:
    if provider == MailProviderChoice.GMAIL:
        if gmail_advanced_oauth:
            return (
                "Advanced Gmail OAuth is for accounts where app passwords are blocked. Use a Google OAuth "
                "client JSON from your own Google Cloud project."
            )
        return (
            "For personal Gmail, paste a Google app password, not your normal Google password. It is saved "
            "to the OS credential store and this field is cleared after setup."
        )
    if provider == MailProviderChoice.OUTLOOK:
        return (
            "Outlook scanning uses Microsoft device-code sign-in and a free Microsoft application client ID. "
            "Normal mailbox passwords are not stored here."
        )
    if provider == MailProviderChoice.OTHER_EMAIL:
        return (
            "Use IMAP only for providers that support app passwords or mail tokens. Store that secret in the "
            "OS credential store first, then enter the secret name here."
        )
    return "Choose Gmail, Outlook, or Other Email to see only the setup fields needed for that provider."


def provider_setup_steps(provider: MailProviderChoice | None, gmail_advanced_oauth: bool = False) -> tuple[str, ...]:
    if provider == MailProviderChoice.GMAIL:
        if gmail_advanced_oauth:
            return (
                "Use advanced Gmail OAuth only when a personal Google app password is blocked.",
                "Create the OAuth client JSON in your own Google Cloud project; do not download credentials from anyone else.",
                "The app stores OAuth tokens in the OS credential store and never logs token values.",
            )
        return (
            "Personal Gmail: use a Google app password. No JSON import file is needed.",
            "Turn on Google 2-Step Verification, then create an app password for Mail.",
            "Paste the 16-character app password here. Do not paste your normal Google password.",
        )
    if provider == MailProviderChoice.OUTLOOK:
        return (
            "Outlook uses Microsoft device-code sign-in with a free application client ID.",
            "Do not paste your normal Outlook password into this app.",
            "If the client ID step is confusing, start with Gmail or Other Email until Outlook setup is simplified.",
        )
    if provider == MailProviderChoice.OTHER_EMAIL:
        return (
            "Use this only when your provider supports IMAP app passwords or mail tokens.",
            "Save the app password in the OS credential store first, then enter the secret name here.",
            "Do not enter your normal mailbox password unless your provider explicitly requires a mail app password.",
        )
    return (
        "Choose Gmail, Outlook, or Other Email.",
        "Scan one mailbox at a time and only scan a second person when they are present and asked for help.",
    )


def provider_setup_actions(provider: MailProviderChoice | None, gmail_advanced_oauth: bool = False) -> tuple[ProviderSetupAction, ...]:
    if provider == MailProviderChoice.GMAIL:
        if gmail_advanced_oauth:
            return (
                ProviderSetupAction("Open Google Cloud credentials", "https://console.cloud.google.com/apis/credentials"),
                ProviderSetupAction("Open Gmail OAuth help", "https://support.google.com/cloud/answer/6158849"),
            )
        return (
            ProviderSetupAction("Open Google App Passwords", "https://myaccount.google.com/apppasswords"),
            ProviderSetupAction("Open Google 2-Step Verification", "https://myaccount.google.com/signinoptions/two-step-verification"),
        )
    if provider == MailProviderChoice.OUTLOOK:
        return (
            ProviderSetupAction(
                "Open Microsoft app registration help",
                "https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app",
            ),
        )
    return ()


def build_provider_or_error(settings: MailProviderSettings) -> tuple[MailProvider | None, UserFacingSetupError | None]:
    if settings.provider == MailProviderChoice.GMAIL:
        client_secret_file = settings.gmail_client_secret_file.strip()
        client_secret_path = Path(client_secret_file).expanduser()
        if settings.gmail_advanced_oauth:
            if not client_secret_file or not client_secret_path.exists():
                return None, UserFacingSetupError(
                    user_message=(
                        "Choose your Gmail OAuth client JSON file before starting the advanced scan. "
                        "For personal Gmail, app password setup is simpler."
                    ),
                    technical_details=SETUP_DETAIL_MISSING_CLIENT_SECRET_FILE,
                )
            from .oauth_mail import GmailApiMailProvider, GmailOAuthConfig

            return GmailApiMailProvider(GmailOAuthConfig(str(client_secret_path))), None
        if client_secret_file and client_secret_path.exists():
            from .oauth_mail import GmailApiMailProvider, GmailOAuthConfig

            return GmailApiMailProvider(GmailOAuthConfig(str(client_secret_path))), None

        username = settings.username.strip()
        app_password = _normalize_gmail_app_password(settings.gmail_app_password)
        secret_name = settings.gmail_secret_name.strip() or _gmail_secret_name(username)
        if not username:
            return None, UserFacingSetupError(
                user_message="Enter your Gmail address before starting the scan.",
                technical_details=SETUP_DETAIL_MISSING_GMAIL_APP_PASSWORD,
            )
        if app_password and not _gmail_app_password_is_plausible(app_password):
            return None, UserFacingSetupError(
                user_message=(
                    "That does not look like a Google app password. Create a 16-character app password for Mail "
                    "and do not paste your normal Google password."
                ),
                technical_details=SETUP_DETAIL_INVALID_GMAIL_APP_PASSWORD,
            )
        try:
            from .secure_store import get_secret, set_secret

            if app_password:
                set_secret(secret_name, app_password)
                password = app_password
            else:
                password = _normalize_gmail_app_password(get_secret(secret_name) or "")
        except Exception:
            return None, UserFacingSetupError(
                user_message="The Gmail app password could not be saved or read. Check your credential store and try again.",
                technical_details=SETUP_DETAIL_CREDENTIAL_STORE_UNAVAILABLE,
            )
        if not password:
            return None, UserFacingSetupError(
                user_message=(
                    "Enter a Google app password for Gmail. Do not use your normal Google password. "
                    "If this is a work or school account, your administrator may require OAuth setup instead."
                ),
                technical_details=SETUP_DETAIL_MISSING_GMAIL_APP_PASSWORD,
            )
        if not _gmail_app_password_is_plausible(password):
            return None, UserFacingSetupError(
                user_message=(
                    "The saved Gmail secret does not look like a Google app password. Replace it with a "
                    "16-character app password for Mail."
                ),
                technical_details=SETUP_DETAIL_INVALID_GMAIL_APP_PASSWORD,
            )

        from .email_scanner import ImapEmailScanner, ImapMailboxConfig

        return (
            ImapEmailScanner(
                ImapMailboxConfig(
                    host="imap.gmail.com",
                    username=username,
                    password=password,
                    days_back=0 if settings.gmail_full_mailbox else max(settings.days_back, 1),
                    folder="[Gmail]/All Mail" if settings.gmail_full_mailbox else "INBOX",
                )
            ),
            None,
        )

    if settings.provider == MailProviderChoice.OUTLOOK:
        client_id = settings.graph_client_id.strip()
        if not client_id:
            return None, UserFacingSetupError(
                user_message="Complete Outlook setup before starting the scan.",
                technical_details=SETUP_DETAIL_MISSING_CLIENT_ID,
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
            technical_details=SETUP_DETAIL_MISSING_IMAP_SETUP,
        )

    try:
        from .secure_store import get_secret

        password = get_secret(secret_name)
    except Exception:
        return None, UserFacingSetupError(
            user_message="The saved mail password could not be read. Check your credential store and try again.",
            technical_details=SETUP_DETAIL_CREDENTIAL_STORE_UNAVAILABLE,
        )
    if not password:
        return None, UserFacingSetupError(
            user_message="The saved mail password was not found. Check the saved secret name and try again.",
            technical_details=SETUP_DETAIL_MISSING_SAVED_IMAP_SECRET,
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


def _normalize_gmail_app_password(app_password: str) -> str:
    return "".join(app_password.split())


def _gmail_app_password_is_plausible(app_password: str) -> bool:
    return len(app_password) == 16 and app_password.isascii() and app_password.isalnum()


def _gmail_secret_name(username: str) -> str:
    safe_username = username.strip().lower() or "gmail"
    return f"gmail-imap-app-password:{safe_username}"


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
        return ScanSummary.from_findings(findings, discovered_count=discovered_count, discovered_accounts=accounts)


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


class GuiPasswordExposureService:
    def __init__(self, checker: HibpBreachChecker | None = None, session_key: bytes | None = None) -> None:
        self.checker = checker or HibpBreachChecker()
        self._session_key = session_key or secrets.token_bytes(32)
        self._checked_results: dict[str, GuiPasswordExposureResult] = {}

    def check_password(self, password: str, confirmed_old_or_reused: bool = False) -> GuiPasswordExposureResult:
        if not password:
            return GuiPasswordExposureResult(
                count=None,
                user_message="Enter a password to check. It will be cleared after the check.",
            )
        if not confirmed_old_or_reused:
            return GuiPasswordExposureResult(
                count=None,
                user_message=(
                    "Only check an old or reused password. Do not check a new generated password; save new "
                    "passwords directly in your vaults."
                ),
                technical_details="password_exposure_confirmation_required",
            )
        fingerprint = self._session_fingerprint(password)
        previous_result = self._checked_results.get(fingerprint)
        if previous_result is not None:
            if previous_result.count and previous_result.count > 0:
                previous_summary = (
                    f"Previous result: found {previous_result.count} time(s). Rotate accounts where you reused it."
                )
            elif previous_result.count == 0:
                previous_summary = "Previous result: not found in HIBP Pwned Passwords."
            else:
                previous_summary = "Previous result: no completed exposure count was stored."
            return GuiPasswordExposureResult(
                count=previous_result.count,
                user_message=(
                    "This password was already checked in this app session, so it was not sent again. "
                    f"{previous_summary}"
                ),
                rotation_recommended=previous_result.rotation_recommended,
                technical_details="password_exposure_duplicate_session_check",
            )
        try:
            count = self.checker.pwned_password_count(password)
        except Exception:
            return GuiPasswordExposureResult(
                count=None,
                user_message="The password exposure check could not finish. Try again later.",
                technical_details="pwned_password_check_failed",
            )
        if count > 0:
            result = GuiPasswordExposureResult(
                count=count,
                user_message=(
                    f"This password appears {count} time(s) in HIBP Pwned Passwords. "
                    "Do not use it; rotate any account where you used it."
                ),
                rotation_recommended=True,
            )
            self._checked_results[fingerprint] = result
            return result
        result = GuiPasswordExposureResult(
            count=0,
            user_message="This password was not found in HIBP Pwned Passwords.",
            rotation_recommended=False,
        )
        self._checked_results[fingerprint] = result
        return result

    def _session_fingerprint(self, password: str) -> str:
        return hmac.new(self._session_key, password.encode("utf-8"), hashlib.sha256).hexdigest()


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

    def prepare_guided_sync(self, candidate: PasswordCandidate, destination: Path) -> GuiVaultWriteResult:
        bitwarden_result = self.write_bitwarden(candidate)
        if bitwarden_result.status.bitwarden != "updated":
            return GuiVaultWriteResult(
                status=VaultSyncStatus(
                    bitwarden=bitwarden_result.status.bitwarden,
                    nordpass="import_needed",
                    verification="pending",
                ),
                user_message=(
                    f"{bitwarden_result.user_message} NordPass CSV was not created, so no plaintext import "
                    "file was left behind."
                ),
                technical_details=bitwarden_result.technical_details,
            )

        nordpass_result = self.stage_nordpass_import(candidate, destination)
        return GuiVaultWriteResult(
            status=VaultSyncStatus(
                bitwarden="updated",
                nordpass=nordpass_result.status.nordpass,
                verification="pending",
                csv_path=nordpass_result.status.csv_path,
            ),
            user_message=f"{bitwarden_result.user_message} {nordpass_result.user_message}",
            technical_details=nordpass_result.technical_details,
        )

    def stage_nordpass_import(self, candidate: PasswordCandidate, destination: Path) -> GuiVaultWriteResult:
        try:
            csv_path = self.nordpass.stage_import([candidate], destination)
        except Exception:
            return GuiVaultWriteResult(
                status=VaultSyncStatus(bitwarden="not_configured", nordpass="export_needed", verification="pending"),
                user_message="NordPass import CSV could not be prepared. Check the destination folder and try again.",
                technical_details="nordpass_csv_stage_failed",
            )
        return GuiVaultWriteResult(
            status=VaultSyncStatus(
                bitwarden="not_configured",
                nordpass="csv_prepared",
                verification="pending",
                csv_path=str(csv_path),
            ),
            user_message=(
                "NordPass import CSV is ready. Import it into NordPass, verify the entry, then delete the CSV."
            ),
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
