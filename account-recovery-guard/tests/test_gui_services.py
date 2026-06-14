from email.message import EmailMessage
import sys
import types

from account_recovery_guard.gui_services import (
    GuiPasswordExposureService,
    GuiRotationService,
    GuiScanService,
    GuiVaultService,
    GuiVaultWriteResult,
    MailProviderSettings,
    SAFE_SCAN_FAILURE_MESSAGE,
    SETUP_DETAIL_SCAN_CONSENT_REQUIRED,
    SETUP_DETAIL_SECOND_PERSON_CONSENT_REQUIRED,
    build_provider_or_error,
    controlled_setup_detail_for_log,
    describe_provider_setup,
    provider_setup_note,
    provider_setup_actions,
    provider_setup_steps,
    scan_progress_stages,
    visible_setup_fields,
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


class FakeNordPassFailure:
    def stage_import(self, candidates, destination):
        raise OSError("disk full password=Secret123!")


class FakePwnedPasswordChecker:
    def __init__(self, count=0, failure=False):
        self.count = count
        self.failure = failure
        self.seen_password = None
        self.call_count = 0

    def pwned_password_count(self, password):
        self.call_count += 1
        self.seen_password = password
        if self.failure:
            raise RuntimeError("network failed password=hunter2")
        return self.count


def test_describe_provider_setup_keeps_gmail_plain_language():
    setup = describe_provider_setup(MailProviderChoice.GMAIL)

    assert setup.title == "Continue with Gmail"
    assert "OAuth" not in setup.description
    assert "app password" in setup.description
    assert setup.advanced is False


def test_describe_provider_setup_marks_other_email_advanced():
    setup = describe_provider_setup(MailProviderChoice.OTHER_EMAIL)

    assert setup.title == "Other email"
    assert setup.advanced is True
    assert "IMAP" in setup.technical_details


def test_visible_setup_fields_keep_gmail_simple_by_default():
    fields = visible_setup_fields(MailProviderChoice.GMAIL)

    assert "person_label" in fields
    assert "username" in fields
    assert "gmail_app_password" in fields
    assert "gmail_full_mailbox" in fields
    assert "gmail_client_secret_file" not in fields
    assert "graph_client_id" not in fields
    assert "imap_host" not in fields


def test_visible_setup_fields_show_gmail_oauth_only_when_enabled():
    fields = visible_setup_fields(MailProviderChoice.GMAIL, gmail_advanced_oauth=True)

    assert "gmail_client_secret_file" in fields
    assert "gmail_app_password" in fields


def test_visible_setup_fields_are_provider_specific():
    outlook = visible_setup_fields(MailProviderChoice.OUTLOOK)
    other = visible_setup_fields(MailProviderChoice.OTHER_EMAIL)

    assert "person_label" in outlook
    assert "person_label" in other
    assert "graph_client_id" in outlook
    assert "gmail_app_password" not in outlook
    assert "imap_host" in other
    assert "graph_client_id" not in other


def test_provider_setup_note_explains_safe_secret_handling():
    gmail_note = provider_setup_note(MailProviderChoice.GMAIL)
    other_note = provider_setup_note(MailProviderChoice.OTHER_EMAIL)

    assert "normal Google password" in gmail_note
    assert "OS credential store" in gmail_note
    assert "OS credential store" in other_note


def test_provider_setup_steps_explain_gmail_without_json_or_normal_password():
    steps = provider_setup_steps(MailProviderChoice.GMAIL)
    text = " ".join(steps)

    assert "No JSON import file is needed" in text
    assert "16-character app password" in text
    assert "normal Google password" in text


def test_provider_setup_steps_keep_advanced_oauth_explicit():
    steps = provider_setup_steps(MailProviderChoice.GMAIL, gmail_advanced_oauth=True)
    text = " ".join(steps)

    assert "advanced Gmail OAuth" in text
    assert "OAuth client JSON" in text
    assert "token values" in text


def test_provider_setup_steps_warn_outlook_and_other_email_about_normal_passwords():
    outlook = " ".join(provider_setup_steps(MailProviderChoice.OUTLOOK))
    other = " ".join(provider_setup_steps(MailProviderChoice.OTHER_EMAIL))

    assert "normal Outlook password" in outlook
    assert "normal mailbox password" in other
    assert "OS credential store" in other


def test_provider_setup_actions_open_only_official_https_setup_pages():
    gmail = provider_setup_actions(MailProviderChoice.GMAIL)
    gmail_advanced = provider_setup_actions(MailProviderChoice.GMAIL, gmail_advanced_oauth=True)
    outlook = provider_setup_actions(MailProviderChoice.OUTLOOK)
    other = provider_setup_actions(MailProviderChoice.OTHER_EMAIL)

    all_actions = gmail + gmail_advanced + outlook
    assert any(action.url == "https://myaccount.google.com/apppasswords" for action in gmail)
    assert any("learn.microsoft.com" in action.url for action in outlook)
    assert other == ()
    assert all(action.url.startswith("https://") for action in all_actions)
    assert all(
        any(domain in action.url for domain in ("google.com", "cloud.google.com", "learn.microsoft.com"))
        for action in all_actions
    )


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


def test_gmail_provider_factory_explains_missing_app_password():
    provider, error = build_provider_or_error(MailProviderSettings(provider=MailProviderChoice.GMAIL))

    assert provider is None
    assert error is not None
    assert "Gmail address" in error.user_message
    assert "gmail_app_password" in error.technical_details


def test_gmail_provider_factory_uses_app_password_for_full_mailbox(monkeypatch):
    stored = {}

    secure_store = types.ModuleType("account_recovery_guard.secure_store")
    secure_store.set_secret = lambda name, value: stored.__setitem__(name, value)
    secure_store.get_secret = lambda name: stored.get(name)
    monkeypatch.setitem(sys.modules, "account_recovery_guard.secure_store", secure_store)

    provider, error = build_provider_or_error(
        MailProviderSettings(
            provider=MailProviderChoice.GMAIL,
            username="You@Gmail.com",
            gmail_app_password="abcd efgh ijkl mnop",
            gmail_full_mailbox=True,
        )
    )

    assert error is None
    assert provider is not None
    assert provider.config.host == "imap.gmail.com"
    assert provider.config.username == "You@Gmail.com"
    assert provider.config.password == "abcdefghijklmnop"
    assert provider.config.folder == "[Gmail]/All Mail"
    assert provider.config.days_back == 0
    assert stored["gmail-imap-app-password:you@gmail.com"] == "abcdefghijklmnop"


def test_gmail_provider_factory_rejects_normal_password_before_storage(monkeypatch):
    stored = {}

    secure_store = types.ModuleType("account_recovery_guard.secure_store")
    secure_store.set_secret = lambda name, value: stored.__setitem__(name, value)
    secure_store.get_secret = lambda name: stored.get(name)
    monkeypatch.setitem(sys.modules, "account_recovery_guard.secure_store", secure_store)

    provider, error = build_provider_or_error(
        MailProviderSettings(
            provider=MailProviderChoice.GMAIL,
            username="you@gmail.com",
            gmail_app_password="my normal password!",
        )
    )

    assert provider is None
    assert error is not None
    assert "does not look like a Google app password" in error.user_message
    assert "normal Google password" in error.user_message
    assert error.technical_details == "invalid_gmail_app_password"
    assert stored == {}
    assert "my normal password" not in error.user_message
    assert "my normal password" not in error.technical_details


def test_gmail_provider_factory_rejects_invalid_saved_secret_without_echo(monkeypatch):
    secure_store = types.ModuleType("account_recovery_guard.secure_store")
    secure_store.set_secret = lambda name, value: None
    secure_store.get_secret = lambda name: "normal-password-with-symbols!"
    monkeypatch.setitem(sys.modules, "account_recovery_guard.secure_store", secure_store)

    provider, error = build_provider_or_error(
        MailProviderSettings(
            provider=MailProviderChoice.GMAIL,
            username="you@gmail.com",
        )
    )

    assert provider is None
    assert error is not None
    assert "saved Gmail secret" in error.user_message
    assert "16-character app password" in error.user_message
    assert error.technical_details == "invalid_gmail_app_password"
    assert "normal-password" not in error.user_message
    assert "normal-password" not in error.technical_details


def test_outlook_provider_factory_explains_missing_client_id():
    provider, error = build_provider_or_error(MailProviderSettings(provider=MailProviderChoice.OUTLOOK))

    assert provider is None
    assert error is not None
    assert "Outlook setup" in error.user_message
    assert "client_id" in error.technical_details


def test_setup_detail_logging_requires_exact_internal_code():
    assert controlled_setup_detail_for_log("missing_client_id") == "missing_client_id"
    assert controlled_setup_detail_for_log(SETUP_DETAIL_SCAN_CONSENT_REQUIRED) == SETUP_DETAIL_SCAN_CONSENT_REQUIRED
    assert controlled_setup_detail_for_log("missing_client_id token=super-secret-value") == ""
    assert controlled_setup_detail_for_log("backend mentioned client_id but token=super-secret-value") == ""


def test_imap_provider_factory_handles_credential_store_exception(monkeypatch):
    def raise_backend_error(secret_name):
        raise RuntimeError("backend exploded token=super-secret-value")

    secure_store = types.ModuleType("account_recovery_guard.secure_store")
    secure_store.get_secret = raise_backend_error
    monkeypatch.setitem(sys.modules, "account_recovery_guard.secure_store", secure_store)

    provider, error = build_provider_or_error(
        MailProviderSettings(
            provider=MailProviderChoice.OTHER_EMAIL,
            username="you@example.com",
            imap_host="imap.example.com",
            imap_secret_name="mail-secret",
        )
    )

    assert provider is None
    assert error is not None
    assert "saved mail password" in error.user_message
    assert error.technical_details == "credential_store_unavailable"
    assert "backend exploded" not in error.user_message
    assert "super-secret-value" not in error.user_message
    assert "backend exploded" not in error.technical_details
    assert "super-secret-value" not in error.technical_details


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


def test_second_person_consent_detail_is_controlled_for_logging():
    assert controlled_setup_detail_for_log(SETUP_DETAIL_SECOND_PERSON_CONSENT_REQUIRED) == SETUP_DETAIL_SECOND_PERSON_CONSENT_REQUIRED
    assert controlled_setup_detail_for_log("second person token=secret") == ""


def test_rotation_service_builds_five_choices_for_account():
    rotation = GuiRotationService().start("Dropbox", "me@example.com", "https://dropbox.com")

    assert len(rotation.choices) == 5
    assert rotation.selected_index is None
    assert {choice.password for choice in rotation.choices}
    assert len({choice.password for choice in rotation.choices}) == 5


def test_password_exposure_service_reports_found_without_revealing_password():
    checker = FakePwnedPasswordChecker(count=12)
    result = GuiPasswordExposureService(checker=checker).check_password("hunter2", confirmed_old_or_reused=True)

    assert checker.seen_password == "hunter2"
    assert result.count == 12
    assert result.rotation_recommended is True
    assert "12" in result.user_message
    assert "hunter2" not in result.user_message
    assert "hunter2" not in repr(result)


def test_password_exposure_service_reports_not_found():
    result = GuiPasswordExposureService(checker=FakePwnedPasswordChecker(count=0)).check_password(
        "unique-password",
        confirmed_old_or_reused=True,
    )

    assert result.count == 0
    assert result.rotation_recommended is False
    assert "not found" in result.user_message.lower()
    assert "unique-password" not in result.user_message


def test_password_exposure_service_reuses_session_result_without_network_or_plaintext():
    checker = FakePwnedPasswordChecker(count=12)
    service = GuiPasswordExposureService(checker=checker, session_key=b"test-session-key")

    first = service.check_password("hunter2", confirmed_old_or_reused=True)
    second = service.check_password("hunter2", confirmed_old_or_reused=True)

    assert checker.call_count == 1
    assert first.count == 12
    assert second.count == 12
    assert second.rotation_recommended is True
    assert second.technical_details == "password_exposure_duplicate_session_check"
    assert "already checked" in second.user_message
    assert "sent again" in second.user_message
    assert "hunter2" not in second.user_message
    assert "hunter2" not in repr(second)
    assert "hunter2" not in repr(service)


def test_password_exposure_session_fingerprint_is_keyed_and_not_plain_hash():
    password = "hunter2"
    first = GuiPasswordExposureService(checker=FakePwnedPasswordChecker(), session_key=b"first-key")
    second = GuiPasswordExposureService(checker=FakePwnedPasswordChecker(), session_key=b"second-key")

    first_fingerprint = first._session_fingerprint(password)
    second_fingerprint = second._session_fingerprint(password)

    assert first_fingerprint != second_fingerprint
    assert password not in first_fingerprint
    assert len(first_fingerprint) == 64


def test_password_exposure_service_handles_empty_and_failure_without_secret_echo():
    empty = GuiPasswordExposureService(checker=FakePwnedPasswordChecker(count=0)).check_password("")
    failure = GuiPasswordExposureService(checker=FakePwnedPasswordChecker(failure=True)).check_password(
        "hunter2",
        confirmed_old_or_reused=True,
    )

    assert empty.count is None
    assert "Enter a password" in empty.user_message
    assert failure.count is None
    assert failure.technical_details == "pwned_password_check_failed"
    assert "hunter2" not in failure.user_message
    assert "hunter2" not in failure.technical_details


def test_password_exposure_service_requires_old_or_reused_confirmation_before_network_call():
    checker = FakePwnedPasswordChecker(count=12)

    result = GuiPasswordExposureService(checker=checker).check_password("new-generated-password")

    assert checker.seen_password is None
    assert result.count is None
    assert result.technical_details == "password_exposure_confirmation_required"
    assert "old or reused password" in result.user_message
    assert "new-generated-password" not in result.user_message


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


def test_vault_service_stages_nordpass_import_without_echoing_password(tmp_path):
    candidate = PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Secret123!", "note")
    destination = tmp_path / "nordpass-import.csv"

    result = GuiVaultService(bitwarden=None).stage_nordpass_import(candidate, destination)

    assert result.status.nordpass == "csv_prepared"
    assert result.status.requires_csv_cleanup is True
    assert result.status.csv_path == str(destination)
    assert destination.exists()
    assert "Secret123" not in result.user_message
    assert "Secret123" not in result.technical_details
    assert "delete the CSV" in result.user_message


def test_guided_vault_sync_does_not_stage_nordpass_when_bitwarden_is_not_ready(tmp_path):
    candidate = PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Secret123!", "note")
    destination = tmp_path / "nordpass-import.csv"

    result = GuiVaultService(bitwarden=None).prepare_guided_sync(candidate, destination)

    assert result.status.bitwarden == "not_configured"
    assert result.status.nordpass == "import_needed"
    assert result.status.csv_path is None
    assert not result.status.requires_csv_cleanup
    assert not destination.exists()
    assert "CSV was not created" in result.user_message
    assert "Secret123" not in result.user_message


def test_guided_vault_sync_stages_nordpass_only_after_bitwarden_success(tmp_path):
    candidate = PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Secret123!", "note")
    destination = tmp_path / "nordpass-import.csv"

    result = GuiVaultService(bitwarden=FakeBitwardenSuccess()).prepare_guided_sync(candidate, destination)

    assert result.status.bitwarden == "updated"
    assert result.status.nordpass == "csv_prepared"
    assert result.status.csv_path == str(destination)
    assert result.status.requires_csv_cleanup
    assert destination.exists()
    assert "Secret123" not in result.user_message


def test_guided_vault_sync_does_not_require_cleanup_when_csv_stage_fails(tmp_path):
    candidate = PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Secret123!", "note")
    destination = tmp_path / "nordpass-import.csv"

    result = GuiVaultService(bitwarden=FakeBitwardenSuccess(), nordpass=FakeNordPassFailure()).prepare_guided_sync(
        candidate,
        destination,
    )

    assert result.status.bitwarden == "updated"
    assert result.status.nordpass == "export_needed"
    assert result.status.csv_path is None
    assert not result.status.requires_csv_cleanup
    assert not destination.exists()
    assert "Secret123" not in result.user_message
    assert result.technical_details == "nordpass_csv_stage_failed"


def test_vault_service_sanitizes_failure_details():
    candidate = PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Secret123!", "note")

    result = GuiVaultService(bitwarden=FakeBitwardenFailure()).write_bitwarden(candidate)

    assert result.status.bitwarden == "verification_failed"
    assert "BW_SESSION is not set" in result.user_message
    assert "super-secret-value" not in result.user_message
    assert "super-secret-value" not in result.technical_details
