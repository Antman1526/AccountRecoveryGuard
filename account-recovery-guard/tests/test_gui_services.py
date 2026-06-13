from email.message import EmailMessage

from account_recovery_guard.gui_services import GuiRotationService, GuiScanService, describe_provider_setup
from account_recovery_guard.gui_state import MailProviderChoice


class FakeMailProvider:
    def fetch_messages(self, days_back: int = 30):
        message = EmailMessage()
        message["Subject"] = "Suspicious login detected"
        message["From"] = "Dropbox Security <security@dropbox.com>"
        message["Date"] = "Sat, 13 Jun 2026 12:00:00 +0000"
        message.set_content("We noticed a suspicious login. Reset your password at https://dropbox.com/reset")
        return [message]


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


def test_scan_service_returns_guided_summary_from_provider_messages():
    service = GuiScanService(provider=FakeMailProvider())

    summary = service.scan(days_back=30)

    assert summary.accounts_needing_attention == 1
    assert summary.recommended is not None
    assert summary.recommended.service_name == "dropbox"
    assert summary.total_accounts_found >= 1


def test_rotation_service_builds_five_choices_for_account():
    rotation = GuiRotationService().start("Dropbox", "me@example.com", "https://dropbox.com")

    assert len(rotation.choices) == 5
    assert rotation.selected_index is None
    assert {choice.password for choice in rotation.choices}
