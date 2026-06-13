from email.message import EmailMessage

from account_recovery_guard.gui_services import (
    GuiRotationService,
    GuiScanService,
    GuiVaultService,
    GuiVaultWriteResult,
    MailProviderSettings,
    SAFE_SCAN_FAILURE_MESSAGE,
    build_provider_or_error,
    describe_provider_setup,
    scan_progress_stages,
)
from account_recovery_guard.gui_state import MailProviderChoice
from account_recovery_guard.models import DiscoveredAccount, PasswordCandidate
from account_recovery_guard.vaults import VaultError


class FakeMailProvider:
    def fetch_messages(self, days_back: int = 30):
        message = EmailMessage()
        message["Subject"] = "Suspicious login detected"
        message["From"] = "Dropbox Security <security@dropbox.com>"
        message["Date"] = "Sat, 13 Jun 2026 12:00:00 +0000"
        message.set_content("We noticed a suspicious login. Reset your password at https://dropbox.com/reset")
        return [message]


class FakeDiscovery:
    def discover(self, messages):
        return [DiscoveredAccount("github", "github.com", 2, "high", ["account verification email"])]


class FakeBitwardenSuccess:
    def upsert_login(self, candidate):
        return None


class FakeBitwardenFailure:
    def upsert_login(self, candidate):
        raise VaultError("BW_SESSION is not set. token=super-secret-value")


def test_describe_provider_setup_keeps_gmail_plain_language():
    setup = describe_provider_setup(MailProviderChoice.GMAIL)

    assert setup.title == "Continue with Gmail"
    assert "OAuth" not in setup.description
    assert setup.advanced is False


def test_describe_provider_setup_marks_other_email_advanced():
    setup = describe_provider_setup(MailProviderChoice.OTHER_EMAIL)

    assert setup.title == "Other email"
    assert setup.advanced is True
    assert "IMAP" in setup.technical_details


def test_scan_progress_stages_are_plain_language():
    stages = scan_progress_stages()

    assert stages == [
        "Connecting to mailbox",
        "Reading recent account and security messages",
        "Finding websites tied to this email",
        "Looking for risk signals",
        "Preparing recommendations",
    ]
    assert all("IMAP" not in stage and "OAuth" not in stage for stage in stages)


def test_gmail_provider_factory_explains_missing_client_secret():
    provider, error = build_provider_or_error(MailProviderSettings(provider=MailProviderChoice.GMAIL))

    assert provider is None
    assert error is not None
    assert "Gmail setup file" in error.user_message
    assert "client_secret_file" in error.technical_details


def test_outlook_provider_factory_explains_missing_client_id():
    provider, error = build_provider_or_error(MailProviderSettings(provider=MailProviderChoice.OUTLOOK))

    assert provider is None
    assert error is not None
    assert "Outlook setup" in error.user_message
    assert "client_id" in error.technical_details


def test_scan_service_returns_guided_summary_from_provider_messages():
    service = GuiScanService(provider=FakeMailProvider())

    summary = service.scan(days_back=30)

    assert summary.accounts_needing_attention == 1
    assert summary.recommended is not None
    assert summary.recommended.service_name == "dropbox"
    assert summary.total_accounts_found >= 1


def test_scan_service_counts_unique_discovered_and_risky_services():
    service = GuiScanService(provider=FakeMailProvider(), discovery=FakeDiscovery())

    summary = service.scan(days_back=30)

    assert summary.total_accounts_found == 2


def test_scan_failure_message_is_generic_for_user_display():
    unsafe_examples = [
        "Authorization: Bearer ya29.secret-token",
        "app password hunter2",
    ]

    assert SAFE_SCAN_FAILURE_MESSAGE == "The scan could not finish. Check your provider setup and try again."
    for unsafe_example in unsafe_examples:
        assert unsafe_example not in SAFE_SCAN_FAILURE_MESSAGE
    assert "ya29.secret-token" not in SAFE_SCAN_FAILURE_MESSAGE
    assert "hunter2" not in SAFE_SCAN_FAILURE_MESSAGE


def test_rotation_service_builds_five_choices_for_account():
    rotation = GuiRotationService().start("Dropbox", "me@example.com", "https://dropbox.com")

    assert len(rotation.choices) == 5
    assert rotation.selected_index is None
    assert {choice.password for choice in rotation.choices}
    assert len({choice.password for choice in rotation.choices}) == 5


def test_vault_service_reports_not_configured_without_cli_call():
    candidate = PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Secret123!", "note")

    result = GuiVaultService(bitwarden=None).write_bitwarden(candidate)

    assert isinstance(result, GuiVaultWriteResult)
    assert result.status.bitwarden == "not_configured"
    assert "Bitwarden" in result.user_message
    assert "Secret123" not in result.user_message


def test_vault_service_reports_success_with_status():
    candidate = PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Secret123!", "note")

    result = GuiVaultService(bitwarden=FakeBitwardenSuccess()).write_bitwarden(candidate)

    assert result.status.bitwarden == "updated"
    assert "updated" in result.user_message.lower()


def test_vault_service_sanitizes_failure_details():
    candidate = PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Secret123!", "note")

    result = GuiVaultService(bitwarden=FakeBitwardenFailure()).write_bitwarden(candidate)

    assert result.status.bitwarden == "verification_failed"
    assert "BW_SESSION is not set" in result.user_message
    assert "super-secret-value" not in result.user_message
    assert "super-secret-value" not in result.technical_details
