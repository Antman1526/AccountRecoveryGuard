from datetime import UTC, datetime

from account_recovery_guard.gui_state import (
    AccountReview,
    GuiAppState,
    MailProviderChoice,
    RotationSession,
    ScanSummary,
    VaultSyncStatus,
)
from account_recovery_guard.models import CompromisedAccountFinding, PasswordCandidate


def test_new_app_starts_in_email_connection_step():
    state = GuiAppState.new()

    assert state.current_step == "connect_email"
    assert state.mail_provider is None
    assert state.scan_summary is None
    assert state.dashboard_available is False


def test_provider_selection_moves_to_consent_without_scanning():
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.GMAIL)

    assert state.current_step == "scan_consent"
    assert state.mail_provider == MailProviderChoice.GMAIL
    assert state.scan_started is False


def test_scan_summary_recommends_highest_risk_finding():
    finding = CompromisedAccountFinding(
        service_name="Dropbox",
        sender_domain="dropbox.com",
        sender="security@dropbox.com",
        subject="Suspicious login",
        timestamp=datetime(2026, 6, 13, tzinfo=UTC),
        severity="high",
        reasons=["suspicious activity", "new login/access alert"],
        reset_link="https://dropbox.com/reset",
        message_id="message-1",
    )
    summary = ScanSummary.from_findings([finding], discovered_count=12)

    assert summary.total_accounts_found == 12
    assert summary.accounts_needing_attention == 1
    assert summary.recommended.service_name == "Dropbox"
    assert summary.headline == "Your scan found 12 accounts"


def test_rotation_session_selects_one_password_without_revealing_all():
    candidates = [
        PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Aa1!" * 8, "note"),
        PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Bb2@" * 8, "note"),
    ]
    session = RotationSession(account=AccountReview.from_finding_stub("Dropbox", "me@example.com"), choices=candidates)

    selected = session.select_choice(2)

    assert selected.selected_index == 2
    assert selected.selected_candidate.password == "Bb2@" * 8
    assert all("Bb2@" not in row.display for row in selected.choice_summaries)


def test_vault_sync_status_guides_nordpass_import_honestly():
    status = VaultSyncStatus(bitwarden="updated", nordpass="csv_prepared", verification="pending")

    assert status.primary_message == "Bitwarden updated. Import the prepared NordPass CSV next."
    assert status.requires_csv_cleanup is True
