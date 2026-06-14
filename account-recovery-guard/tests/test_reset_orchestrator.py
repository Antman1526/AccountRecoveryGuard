from account_recovery_guard.models import CompromisedAccountFinding
from account_recovery_guard.reset_orchestrator import PasswordResetOrchestrator


def _finding(reset_link: str) -> CompromisedAccountFinding:
    return CompromisedAccountFinding(
        service_name="example",
        sender_domain="example.com",
        sender="security@example.com",
        subject="Security alert",
        timestamp=None,
        severity="high",
        reasons=["security alert"],
        reset_link=reset_link,
    )


def test_workflow_allows_safe_reset_link_automation():
    workflow = PasswordResetOrchestrator().build_workflow(_finding("https://example.com/reset"))

    assert workflow.automation_available is True
    assert "failed safety checks" not in workflow.steps[0]


def test_workflow_blocks_unsafe_redirect_reset_link_automation():
    workflow = PasswordResetOrchestrator().build_workflow(
        _finding("https://example.com/reset?continue=https%3A%2F%2Fevil.test%2Fsteal")
    )

    assert workflow.automation_available is False
    assert "failed safety checks" in workflow.steps[0]
