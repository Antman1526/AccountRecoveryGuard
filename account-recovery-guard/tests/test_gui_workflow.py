from account_recovery_guard.gui_workflow import build_command_preview
from account_recovery_guard.gui_workflow import recovery_stages, suggested_next_actions


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
