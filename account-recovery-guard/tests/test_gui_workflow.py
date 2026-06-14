from account_recovery_guard.gui_workflow import build_command_preview
from account_recovery_guard.gui_workflow import password_exposure_prompt_lines
from account_recovery_guard.gui_workflow import recovery_stages, safe_recovery_scope_lines, suggested_next_actions


def test_build_command_preview_escapes_values_for_copyable_cli():
    command = build_command_preview("rotate", {"service": "Example App", "username": "me@example.com", "open": True})

    assert command == "account-recovery-guard rotate --service 'Example App' --username me@example.com --open"


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
    assert "whole web" in text
    assert "dark-web" in text
    assert "private forums" in text


def test_password_exposure_prompt_guides_rotation_without_overreach():
    found_text = " ".join(password_exposure_prompt_lines(12)).lower()
    clean_text = " ".join(password_exposure_prompt_lines(0)).lower()

    assert "where you reused that password" in found_text
    assert "all sites" not in found_text
    assert "suspicious mailbox alerts" in clean_text


def test_safe_recovery_scope_is_clear_on_first_launch():
    text = " ".join(safe_recovery_scope_lines()).lower()

    assert "mailbox evidence" in text
    assert "free hibp" in text
    assert "does not crawl the whole web" in text
    assert "dark-web dumps" in text
    assert "exposing credentials further" in text
    assert "one authorized mailbox" in text
