from datetime import UTC, datetime

from account_recovery_guard.gui_state import (
    AccountReview,
    GuiAppState,
    GuiStep,
    MailProviderChoice,
    RotationSession,
    ScanSummary,
    VaultSyncStatus,
)
from account_recovery_guard.models import CompromisedAccountFinding, PasswordCandidate


def _password_candidates() -> list[PasswordCandidate]:
    return [
        PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Aa1!" * 8, "note"),
        PasswordCandidate("Dropbox", "me@example.com", "https://dropbox.com", "Bb2@" * 8, "note"),
    ]


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


def test_first_run_checklist_starts_with_email_as_next_step():
    state = GuiAppState.new()
    checklist = {item.title: item for item in state.first_run_checklist}

    assert checklist["Connect email"].status == "next"
    assert checklist["Run local scan"].status == "waiting"
    assert checklist["Check password exposure"].status == "available"
    assert "dark" not in " ".join(item.detail for item in state.first_run_checklist).lower()


def test_first_run_checklist_advances_after_provider_and_scan():
    summary = ScanSummary.from_findings([], discovered_count=0)
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.GMAIL).with_scan_summary(summary)
    checklist = {item.title: item for item in state.first_run_checklist}

    assert checklist["Connect email"].status == "done"
    assert checklist["Run local scan"].status == "done"
    assert checklist["Review one account"].status == "done"
    assert checklist["Sync vaults"].status == "waiting"


def test_first_run_checklist_points_to_account_review_when_findings_exist():
    finding = CompromisedAccountFinding(
        service_name="dropbox",
        sender_domain="dropbox.com",
        sender="security@dropbox.com",
        subject="Suspicious login",
        timestamp=datetime(2026, 6, 13, tzinfo=UTC),
        severity="high",
        reasons=["suspicious activity"],
    )
    summary = ScanSummary.from_findings([finding], discovered_count=1)
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.GMAIL).with_scan_summary(summary)
    checklist = {item.title: item for item in state.first_run_checklist}

    assert checklist["Review one account"].status == "next"
    assert "one account at a time" in checklist["Review one account"].detail


def test_password_exposure_count_updates_checklist_without_password_storage():
    clean = GuiAppState.new().with_password_exposure_count(0)
    exposed = GuiAppState.new().with_password_exposure_count(42)

    clean_check = {item.title: item for item in clean.first_run_checklist}
    exposed_check = {item.title: item for item in exposed.first_run_checklist}

    assert clean.password_exposure_count == 0
    assert clean_check["Check password exposure"].status == "done"
    assert "not found" in clean_check["Check password exposure"].detail.lower()
    assert exposed.password_exposure_count == 42
    assert exposed_check["Check password exposure"].status == "done"
    assert exposed_check["Check password exposure"].tone == "attention"
    assert "appears in breach corpuses" in exposed_check["Check password exposure"].detail
    assert "hunter2" not in repr(exposed)


def test_protected_person_label_is_safe_and_nonempty():
    state = GuiAppState.new().with_protected_person("  spouse   mailbox  ")

    assert state.protected_person_label == "spouse mailbox"
    assert state.protected_person_prefix == "spouse mailbox: "


def test_blank_protected_person_label_defaults_to_me():
    state = GuiAppState.new().with_protected_person("   ")

    assert state.protected_person_label == "Me"


def test_long_protected_person_label_is_bounded():
    state = GuiAppState.new().with_protected_person("x" * 100)

    assert len(state.protected_person_label) == 40


def test_scan_cannot_start_without_provider_selection():
    state = GuiAppState.new()

    try:
        state.start_scan()
    except ValueError as exc:
        assert "mail provider" in str(exc)
    else:
        raise AssertionError("start_scan should require a mail provider")


def test_consent_copy_explains_local_scan_boundaries():
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.OUTLOOK)

    summary = state.consent_summary.lower()

    assert "what we scan" in summary
    assert "never log" in summary
    assert "local" in summary


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


def test_scan_summary_builds_ordered_account_reviews_for_results_list():
    high = CompromisedAccountFinding(
        service_name="dropbox",
        sender_domain="dropbox.com",
        sender="security@dropbox.com",
        subject="Suspicious login",
        timestamp=datetime(2026, 6, 13, tzinfo=UTC),
        severity="high",
        reasons=["suspicious activity"],
    )
    medium = CompromisedAccountFinding(
        service_name="github",
        sender_domain="github.com",
        sender="security@github.com",
        subject="New login",
        timestamp=datetime(2026, 6, 13, tzinfo=UTC),
        severity="medium",
        reasons=["new login/access alert"],
    )

    summary = ScanSummary.from_findings([medium, high], discovered_count=2)
    reviews = summary.account_reviews("me@example.com")

    assert [review.service_name for review in reviews] == ["Dropbox", "Github"]
    assert reviews[0].risk_label == "Needs attention"
    assert reviews[1].risk_label == "Review recommended"


def test_scan_summary_next_safest_action_is_plain_language():
    finding = CompromisedAccountFinding(
        service_name="dropbox",
        sender_domain="dropbox.com",
        sender="security@dropbox.com",
        subject="Suspicious login",
        timestamp=datetime(2026, 6, 13, tzinfo=UTC),
        severity="high",
        reasons=["suspicious activity"],
    )

    summary = ScanSummary.from_findings([finding], discovered_count=1)

    assert "Start with Dropbox" in summary.next_safest_action
    assert "rotate only that account first" in summary.next_safest_action
    assert "all accounts" not in summary.next_safest_action.lower()
    assert "hunter2" not in summary.next_safest_action.lower()


def test_empty_scan_summary_next_safest_action_avoids_rotation_pressure():
    summary = ScanSummary.from_findings([], discovered_count=0)

    assert "No urgent alerts" in summary.next_safest_action
    assert "monitoring" in summary.next_safest_action


def test_placeholder_scan_completion_enables_results_and_dashboard():
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.GMAIL).start_scan()

    completed = state.complete_placeholder_scan()

    assert completed.current_step == GuiStep.RESULTS
    assert completed.scan_started is True
    assert completed.scan_summary == ScanSummary.from_findings([], discovered_count=0)
    assert completed.dashboard_available is True


def test_dashboard_requires_scan_summary():
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.GMAIL)

    try:
        state.show_dashboard()
    except ValueError as exc:
        assert "scan summary" in str(exc)
    else:
        raise AssertionError("show_dashboard should require scan results")


def test_results_transition_requires_scan_summary():
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.GMAIL)

    try:
        state.show_results()
    except ValueError as exc:
        assert "scan summary" in str(exc)
    else:
        raise AssertionError("show_results should require scan results")


def test_rotation_placeholder_requires_scan_summary():
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.GMAIL)

    try:
        state.show_guided_rotation_placeholder()
    except ValueError as exc:
        assert "scan results" in str(exc)
    else:
        raise AssertionError("show_guided_rotation_placeholder should require scan results")


def test_dashboard_transition_keeps_summary_available():
    summary = ScanSummary.from_findings([], discovered_count=0)
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.GMAIL).with_scan_summary(summary)

    dashboard = state.show_dashboard()

    assert dashboard.current_step == GuiStep.DASHBOARD
    assert dashboard.scan_summary == summary
    assert dashboard.dashboard_available is True


def test_results_and_rotation_transitions_keep_summary_available():
    summary = ScanSummary.from_findings([], discovered_count=0)
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.GMAIL).with_scan_summary(summary)

    results = state.show_guided_rotation_placeholder().show_results()
    rotation = state.show_guided_rotation_placeholder()

    assert results.current_step == GuiStep.RESULTS
    assert rotation.current_step == GuiStep.ROTATION
    assert results.scan_summary == summary
    assert rotation.scan_summary == summary


def test_account_review_transition_records_selected_account():
    summary = ScanSummary.from_findings([], discovered_count=0)
    account = AccountReview.from_finding_stub("Dropbox", "me@example.com")
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.GMAIL).with_scan_summary(summary)

    review = state.show_account_review(account)

    assert review.current_step == GuiStep.ACCOUNT_REVIEW
    assert review.selected_account == account
    assert review.scan_summary == summary


def test_rotation_transition_records_account_and_session():
    summary = ScanSummary.from_findings([], discovered_count=0)
    account = AccountReview.from_finding_stub("Dropbox", "me@example.com")
    session = RotationSession(account=account, choices=_password_candidates())
    state = GuiAppState.new().with_mail_provider(MailProviderChoice.GMAIL).with_scan_summary(summary)

    rotation = state.start_guided_rotation(account, session)

    assert rotation.current_step == GuiStep.ROTATION
    assert rotation.selected_account == account
    assert rotation.rotation_session == session
    assert rotation.scan_summary == summary


def test_rotation_session_selects_one_password_without_revealing_all():
    candidates = _password_candidates()
    session = RotationSession(account=AccountReview.from_finding_stub("Dropbox", "me@example.com"), choices=candidates)

    selected = session.select_choice(2)

    assert selected.selected_index == 2
    assert selected.selected_candidate.password == "Bb2@" * 8
    for candidate in candidates:
        assert all(candidate.password not in row.display for row in selected.choice_summaries)


def test_rotation_session_repr_does_not_reveal_candidate_passwords():
    candidates = _password_candidates()
    session = RotationSession(account=AccountReview.from_finding_stub("Dropbox", "me@example.com"), choices=candidates)

    session_repr = repr(session)

    assert all(candidate.password not in session_repr for candidate in candidates)


def test_app_state_repr_does_not_reveal_rotation_passwords():
    candidates = _password_candidates()
    session = RotationSession(account=AccountReview.from_finding_stub("Dropbox", "me@example.com"), choices=candidates)
    state = GuiAppState(current_step=GuiStep.ROTATION, rotation_session=session)

    state_repr = repr(state)

    assert all(candidate.password not in state_repr for candidate in candidates)


def test_rotation_session_stores_choices_immutably():
    candidates = _password_candidates()
    session = RotationSession(account=AccountReview.from_finding_stub("Dropbox", "me@example.com"), choices=candidates)

    candidates.append(PasswordCandidate("GitHub", "me@example.com", "https://github.com", "Cc3#" * 8, "note"))

    assert isinstance(session.choices, tuple)
    assert len(session.choices) == 2


def test_vault_sync_status_guides_nordpass_import_honestly():
    status = VaultSyncStatus(bitwarden="updated", nordpass="csv_prepared", verification="pending")

    assert status.primary_message == "Bitwarden updated. Import the prepared NordPass CSV next."
    assert status.requires_csv_cleanup is True


def test_vault_sync_status_cleanup_message_includes_staged_csv_path():
    status = VaultSyncStatus(
        bitwarden="updated",
        nordpass="csv_prepared",
        verification="pending",
        csv_path="/tmp/nordpass.csv",
    )

    assert status.requires_csv_cleanup is True
    assert "/tmp/nordpass.csv" in status.cleanup_message
