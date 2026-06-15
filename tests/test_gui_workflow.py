from account_recovery_guard.gui_workflow import build_command_preview
from account_recovery_guard.gui_workflow import build_review_plan
from account_recovery_guard.gui_workflow import consumer_readiness_rows
from account_recovery_guard.gui_workflow import password_exposure_blocked_message
from account_recovery_guard.gui_workflow import password_exposure_display_message
from account_recovery_guard.gui_workflow import password_exposure_prompt_lines
from account_recovery_guard.gui_workflow import password_exposure_result_summary
from account_recovery_guard.gui_workflow import password_exposure_ready
from account_recovery_guard.gui_workflow import (
    SECRET_REFERENCE_PLACEHOLDER,
    looks_like_direct_secret,
    recovery_stages,
    rotation_copy_ready,
    rotation_copy_confirmation_text,
    reused_password_triage_steps,
    exposure_boundary_rows,
    safe_preview_value,
    review_scope_lines,
    scan_start_ready,
    suggested_next_actions,
    vault_sync_confirmation_texts,
    vault_sync_ready,
)
from account_recovery_guard.gui_state import ScanSummary, VaultSyncStatus
from account_recovery_guard.models import AccountRiskFinding
from account_recovery_guard.readiness import ReadinessCheck


def test_build_command_preview_escapes_values_for_copyable_cli():
    command = build_command_preview("rotate", {"service": "Example App", "username": "me@example.com", "open": True})

    assert command == "account-recovery-guard rotate --service 'Example App' --username me@example.com --open"


def test_build_command_preview_keeps_safe_secret_reference_names():
    command = build_command_preview(
        "scan-imap",
        {
            "host": "imap.example.com",
            "username": "me@example.com",
            "secret_name": "gmail-imap-app-password:me@example.com",
        },
    )

    assert "gmail-imap-app-password:me@example.com" in command
    assert SECRET_REFERENCE_PLACEHOLDER not in command


def test_build_command_preview_redacts_direct_secret_values():
    command = build_command_preview(
        "scan-imap",
        {
            "host": "imap.example.com",
            "username": "me@example.com",
            "secret_name": "abcd efgh ijkl mnop",
        },
    )

    assert "abcd" not in command
    assert SECRET_REFERENCE_PLACEHOLDER in command


def test_build_command_preview_redacts_reset_link_tokens():
    command = build_command_preview(
        "rotate",
        {
            "service": "Example",
            "reset_link": "https://example.com/reset?token=secret-reset-token#continue",
        },
    )

    assert "secret-reset-token" not in command
    assert "#continue" not in command
    assert "https://example.com/reset?<redacted>#<redacted>" in command


def test_build_command_preview_redacts_pasted_oauth_client_secret_json():
    command = build_command_preview(
        "scan-gmail",
        {
            "client_secret_file": '{"installed":{"client_secret":"super-secret-oauth-value"}}',
            "token_secret_name": "gmail-oauth-token",
        },
    )
    file_path_command = build_command_preview(
        "scan-gmail",
        {
            "client_secret_file": "client_secret.json",
            "token_secret_name": "gmail-oauth-token",
        },
    )

    assert "super-secret-oauth-value" not in command
    assert SECRET_REFERENCE_PLACEHOLDER in command
    assert "client_secret.json" in file_path_command
    assert SECRET_REFERENCE_PLACEHOLDER not in file_path_command


def test_safe_preview_value_redacts_password_and_token_like_secret_references():
    assert safe_preview_value("password_secret", "CorrectHorseBatteryStaple!2") == SECRET_REFERENCE_PLACEHOLDER
    assert safe_preview_value("token_secret_name", "access_token=super-secret") == SECRET_REFERENCE_PLACEHOLDER
    assert safe_preview_value("service", "CorrectHorseBatteryStaple!2") == "CorrectHorseBatteryStaple!2"


def test_direct_secret_detection_avoids_plain_saved_secret_names():
    assert looks_like_direct_secret("mail-password-or-token") is False
    assert looks_like_direct_secret("gmail-imap-app-password:you@gmail.com") is False
    assert looks_like_direct_secret("abcd efgh ijkl mnop") is True
    assert looks_like_direct_secret("CorrectHorseBatteryStaple!2") is True


def test_recovery_stages_explain_original_goal_end_to_end():
    stages = recovery_stages()

    assert [stage.title for stage in stages] == [
        "Connect mailboxes",
        "Find risky accounts",
        "Review and rotate",
        "Sync both vaults",
        "Verify and clean up",
    ]
    assert "confirmed risk signal" in stages[2].detail
    assert "Rotate passwords" not in [stage.title for stage in stages]
    assert "exposure-plan" in stages[1].command
    assert "exposure review plan" in stages[1].detail
    assert "safe exposure plan" not in stages[1].detail
    assert "optional HIBP email lookup" in stages[1].detail
    assert "breach intelligence" not in stages[1].detail
    assert stages[3].status == "manual"
    assert "NordPass import" in stages[3].detail


def test_suggested_next_actions_are_user_friendly_and_safe():
    actions = suggested_next_actions()
    text = " ".join(actions).lower()

    assert actions[0].startswith("Start with")
    assert "review the account evidence first" in text
    assert "rotate only if" in text
    assert "rotate one account at a time" not in text
    assert any("Bitwarden" in action and "NordPass" in action for action in actions)
    assert all("plaintext password" not in action.lower() for action in actions)


def test_password_exposure_prompt_explains_free_safe_boundary():
    lines = password_exposure_prompt_lines()
    text = " ".join(lines).lower()

    assert "free hibp" in text
    assert "k-anonymous" in text
    assert "never logged" in text
    assert "reuses the local result" in text
    assert "do not check a new generated password" in text
    assert "whole web" in text
    assert "dark-web" in text
    assert "private forums" in text


def test_password_exposure_prompt_guides_rotation_without_overreach():
    found_text = " ".join(password_exposure_prompt_lines(12)).lower()
    clean_text = " ".join(password_exposure_prompt_lines(0)).lower()

    assert "where you reused that password" in found_text
    assert "all sites" not in found_text
    assert "review suspicious mailbox alerts" in clean_text
    assert "rotate only if" in clean_text
    assert "still rotate accounts" not in clean_text


def test_password_exposure_ready_requires_text_and_confirmation():
    assert password_exposure_ready("", False) is False
    assert password_exposure_ready("old-password", False) is False
    assert password_exposure_ready("", True) is False
    assert password_exposure_ready("old-password", True) is True


def test_scan_start_ready_requires_permission_and_second_person_consent():
    assert scan_start_ready(False) is False
    assert scan_start_ready(True) is True
    assert scan_start_ready(True, second_person_required=True, second_person_confirmed=False) is False
    assert scan_start_ready(True, second_person_required=True, second_person_confirmed=True) is True


def test_password_exposure_blocked_message_discourages_generated_password_checks():
    missing = password_exposure_blocked_message("", False)
    unconfirmed = password_exposure_blocked_message("new-password", False)
    ready = password_exposure_blocked_message("old-password", True)

    assert "Enter an old or reused password" in missing
    assert "Do not check a new generated password" in unconfirmed
    assert "HIBP k-anonymous" in ready
    assert "new-password" not in unconfirmed


def test_rotation_copy_confirmation_distinguishes_verified_and_manual_paths():
    trusted = rotation_copy_confirmation_text(True).lower()
    untrusted = rotation_copy_confirmation_text(False).lower()

    assert "verified reset page" in trusted
    assert "official app" in trusted
    assert "official website or app" in untrusted
    assert "suspicious email link" in untrusted


def test_rotation_copy_ready_requires_confirmation_and_selected_choice():
    assert rotation_copy_ready(False, False) is False
    assert rotation_copy_ready(True, False) is False
    assert rotation_copy_ready(False, True) is False
    assert rotation_copy_ready(True, True) is True


def test_vault_sync_confirmation_requires_real_account_success():
    changed_text, verified_text = vault_sync_confirmation_texts()

    assert "official website or app" in changed_text
    assert "confirmed the new password works" in verified_text
    assert vault_sync_ready(False, False) is False
    assert vault_sync_ready(True, False) is False
    assert vault_sync_ready(False, True) is False
    assert vault_sync_ready(True, True) is True
    assert vault_sync_ready(True, True, selected_password_ready=False) is False
    assert vault_sync_ready(True, True, selected_password_ready=True) is True


def test_review_scope_is_clear_on_first_launch():
    text = " ".join(review_scope_lines()).lower()

    assert "review path is mailbox evidence" in text
    assert "mailbox evidence" in text
    assert "free hibp" in text
    assert "does not crawl the whole web" in text
    assert "dark-web dumps" in text
    assert "helps avoid unsafe sources" in text
    assert "exposing credentials further" in text
    assert "one authorized mailbox" in text
    assert "safe path is mailbox evidence" not in text
    assert "protects you from unsafe sources" not in text


def test_exposure_boundary_rows_prevent_unsafe_whole_web_promise():
    rows = exposure_boundary_rows()
    by_title = {row.title: row for row in rows}
    text = " ".join(row.detail for row in rows).lower()

    assert by_title["What this can check"].status == "review path"
    assert "What this can safely find" not in by_title
    assert "authorized mailbox evidence" in text
    assert "hibp pwned passwords" in text
    assert "cannot promise" in by_title["What this cannot promise"].title.lower()
    assert "every website" in by_title["What this cannot promise"].detail.lower()
    assert "dark-web dumps" in text
    assert "outside this local review workflow" in text
    assert "outside this safe local workflow" not in text
    assert "second person" in text
    assert "Review one mailbox at a time" in by_title["Best use for 1-2 people"].detail
    assert "Protect one mailbox at a time" not in by_title["Best use for 1-2 people"].detail
    assert by_title["What this cannot promise"].tone == "attention"
    assert "all sites where your password is exposed" not in text


def test_password_exposure_result_summary_keeps_known_unknown_clear():
    unchecked = password_exposure_result_summary(None)
    exposed = password_exposure_result_summary(5)
    clean = password_exposure_result_summary(0)

    assert "Known: no password has been checked yet" in unchecked
    assert "Unknown" in unchecked
    assert "appears 5 time(s)" in exposed
    assert "does not know every site" in exposed
    assert "Review where you reused it, then rotate only those accounts one at a time." in exposed
    assert "rotate only those reused accounts" not in exposed
    assert "one at a time" in exposed
    assert "not found in HIBP" in clean
    assert "private breach dumps" in clean
    assert "hunter2" not in exposed + clean + unchecked


def test_password_exposure_display_message_combines_result_with_limits():
    message = password_exposure_display_message(
        5,
        "This password appears 5 time(s) in HIBP Pwned Passwords.",
    )

    assert "This password appears 5 time(s)" in message
    assert "Known: this old password appears 5 time(s)" in message
    assert "Unknown: the app" in message
    assert "does not know every site" in message
    assert "one at a time" in message
    assert "Reused password triage" in message
    assert "Safe reuse triage" not in message
    assert "Do not paste this password into search engines" in message
    assert "password manager search" in message
    assert "hunter2" not in message


def test_reused_password_triage_steps_avoid_unsafe_searching():
    clean_steps = reused_password_triage_steps(0)
    found_steps = reused_password_triage_steps(5)
    text = " ".join(found_steps).lower()

    assert clean_steps == []
    assert "search engines" in text
    assert "paste sites" in text
    assert "dark-web lookups" in text
    assert "password manager search" in text
    assert "official site or app" in text
    assert "second person" in text
    assert "hunter2" not in text


def test_consumer_readiness_rows_keep_free_manual_and_paid_boundaries_clear():
    rows = consumer_readiness_rows(
        (
            ReadinessCheck("OS credential store", "ready", "Secrets use the OS credential store."),
            ReadinessCheck("Staged NordPass CSV cleanup", "action_needed", "Delete the stale CSV."),
            ReadinessCheck("Bitwarden session", "action_needed", "Unlock Bitwarden yourself."),
            ReadinessCheck("NordPass sync", "manual_required", "Import the CSV into NordPass."),
            ReadinessCheck("HIBP email-breach lookup", "paid_optional", "Requires a HIBP API key."),
            ReadinessCheck("macOS app signing", "paid_optional", "Requires Apple Developer."),
        )
    )
    by_title = {row.title: row for row in rows}

    assert by_title["OS credential store"].status == "ready"
    assert by_title["Staged NordPass CSV cleanup"].status == "needs setup"
    assert by_title["Staged NordPass CSV cleanup"].tone == "attention"
    assert by_title["Bitwarden session"].status == "needs setup"
    assert by_title["Bitwarden session"].tone == "attention"
    assert by_title["NordPass sync"].status == "manual"
    assert by_title["HIBP email-breach lookup"].status == "paid optional"
    assert "macOS app signing" not in by_title


def test_review_plan_starts_with_one_authorized_mailbox():
    plan = build_review_plan()

    assert plan.headline == "Start with one authorized mailbox"
    assert "No mailbox scan has run yet" in plan.known
    assert "Connect Gmail" in plan.next_action
    assert "review path" in plan.guardrail
    assert "safe path" not in plan.guardrail
    assert plan.tone == "attention"


def test_review_plan_prioritizes_high_risk_mailbox_alert_without_overclaiming():
    summary = ScanSummary.from_findings(
        [
            AccountRiskFinding(
                service_name="github",
                sender_domain="github.com",
                sender="security@github.com",
                subject="Suspicious login detected",
                timestamp=None,
                severity="high",
                reasons=["suspicious activity"],
            )
        ],
        discovered_count=1,
    )

    plan = build_review_plan(summary)

    assert plan.headline == "Review the highest-risk alert first"
    assert "1 account needs attention" in plan.known
    assert "not proof" in plan.unknown
    assert "Start with Github" in plan.next_action
    assert "official" in plan.guardrail
    assert "all sites" not in " ".join((plan.known, plan.unknown, plan.next_action, plan.guardrail)).lower()


def test_review_plan_for_exposed_reused_password_stays_free_and_specific():
    summary = ScanSummary.from_findings([], discovered_count=3)

    plan = build_review_plan(summary, password_exposure_count=12)

    assert plan.headline == "A reused password needs attention"
    assert "appears in HIBP Pwned Passwords" in plan.known
    assert "does not know every account" in plan.unknown
    assert "where you reused it" in plan.next_action
    assert "free k-anonymous" in plan.guardrail
    assert "whole-web search" in plan.guardrail


def test_review_plan_prioritizes_plaintext_csv_cleanup():
    summary = ScanSummary.from_findings([], discovered_count=0)
    vault_status = VaultSyncStatus(bitwarden="updated", nordpass="csv_prepared", csv_path="/tmp/nordpass.csv")

    plan = build_review_plan(summary, password_exposure_count=0, vault_status=vault_status)

    assert plan.headline == "Finish vault cleanup"
    assert "NordPass import CSV" in plan.known
    assert "delete the staged CSV" in plan.next_action
    assert "plaintext passwords" in plan.guardrail
    assert plan.tone == "attention"


def test_review_plan_for_clean_scan_keeps_uncertainty_visible():
    summary = ScanSummary.from_findings([], discovered_count=0)

    plan = build_review_plan(summary, password_exposure_count=0)

    assert plan.headline == "No urgent alerts found"
    assert "not found in HIBP" in plan.known
    assert "does not prove every account is risk-free" in plan.unknown
    assert "does not prove every account is safe" not in plan.unknown
    assert "unsafe paste sites" in plan.guardrail
