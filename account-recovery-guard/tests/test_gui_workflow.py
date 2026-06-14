from account_recovery_guard.gui_workflow import build_command_preview
from account_recovery_guard.gui_workflow import build_protection_plan
from account_recovery_guard.gui_workflow import consumer_readiness_rows
from account_recovery_guard.gui_workflow import password_exposure_blocked_message
from account_recovery_guard.gui_workflow import password_exposure_prompt_lines
from account_recovery_guard.gui_workflow import password_exposure_ready
from account_recovery_guard.gui_workflow import (
    SECRET_REFERENCE_PLACEHOLDER,
    looks_like_direct_secret,
    recovery_stages,
    rotation_copy_confirmation_text,
    safe_preview_value,
    safe_recovery_scope_lines,
    suggested_next_actions,
    vault_sync_confirmation_texts,
    vault_sync_ready,
)
from account_recovery_guard.gui_state import ScanSummary, VaultSyncStatus
from account_recovery_guard.models import CompromisedAccountFinding
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
        "Rotate passwords",
        "Sync both vaults",
        "Verify and clean up",
    ]
    assert "exposure-plan" in stages[1].command
    assert stages[3].status == "manual"
    assert "NordPass import" in stages[3].detail


def test_suggested_next_actions_are_user_friendly_and_safe():
    actions = suggested_next_actions()

    assert actions[0].startswith("Start with")
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
    assert "suspicious mailbox alerts" in clean_text


def test_password_exposure_ready_requires_text_and_confirmation():
    assert password_exposure_ready("", False) is False
    assert password_exposure_ready("old-password", False) is False
    assert password_exposure_ready("", True) is False
    assert password_exposure_ready("old-password", True) is True


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


def test_vault_sync_confirmation_requires_real_account_success():
    changed_text, verified_text = vault_sync_confirmation_texts()

    assert "official website or app" in changed_text
    assert "confirmed the new password works" in verified_text
    assert vault_sync_ready(False, False) is False
    assert vault_sync_ready(True, False) is False
    assert vault_sync_ready(False, True) is False
    assert vault_sync_ready(True, True) is True


def test_safe_recovery_scope_is_clear_on_first_launch():
    text = " ".join(safe_recovery_scope_lines()).lower()

    assert "mailbox evidence" in text
    assert "free hibp" in text
    assert "does not crawl the whole web" in text
    assert "dark-web dumps" in text
    assert "exposing credentials further" in text
    assert "one authorized mailbox" in text


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


def test_protection_plan_starts_with_one_authorized_mailbox():
    plan = build_protection_plan()

    assert plan.headline == "Start with one authorized mailbox"
    assert "No mailbox scan has run yet" in plan.known
    assert "Connect Gmail" in plan.next_action
    assert "safe path" in plan.guardrail
    assert plan.tone == "attention"


def test_protection_plan_prioritizes_high_risk_mailbox_alert_without_overclaiming():
    summary = ScanSummary.from_findings(
        [
            CompromisedAccountFinding(
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

    plan = build_protection_plan(summary)

    assert plan.headline == "Review the highest-risk alert first"
    assert "1 account needs attention" in plan.known
    assert "not proof" in plan.unknown
    assert "Start with Github" in plan.next_action
    assert "official" in plan.guardrail
    assert "all sites" not in " ".join((plan.known, plan.unknown, plan.next_action, plan.guardrail)).lower()


def test_protection_plan_for_exposed_reused_password_stays_free_and_specific():
    summary = ScanSummary.from_findings([], discovered_count=3)

    plan = build_protection_plan(summary, password_exposure_count=12)

    assert plan.headline == "A reused password needs attention"
    assert "appears in HIBP Pwned Passwords" in plan.known
    assert "does not know every account" in plan.unknown
    assert "where you reused it" in plan.next_action
    assert "free k-anonymous" in plan.guardrail
    assert "whole-web search" in plan.guardrail


def test_protection_plan_prioritizes_plaintext_csv_cleanup():
    summary = ScanSummary.from_findings([], discovered_count=0)
    vault_status = VaultSyncStatus(bitwarden="updated", nordpass="csv_prepared", csv_path="/tmp/nordpass.csv")

    plan = build_protection_plan(summary, password_exposure_count=0, vault_status=vault_status)

    assert plan.headline == "Finish vault cleanup"
    assert "NordPass import CSV" in plan.known
    assert "delete the staged CSV" in plan.next_action
    assert "plaintext passwords" in plan.guardrail
    assert plan.tone == "attention"


def test_protection_plan_for_clean_scan_keeps_uncertainty_visible():
    summary = ScanSummary.from_findings([], discovered_count=0)

    plan = build_protection_plan(summary, password_exposure_count=0)

    assert plan.headline == "No urgent alerts found"
    assert "not found in HIBP" in plan.known
    assert "does not prove every account is safe" in plan.unknown
    assert "unsafe paste sites" in plan.guardrail
