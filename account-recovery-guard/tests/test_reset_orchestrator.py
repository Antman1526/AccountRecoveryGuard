import pytest

from account_recovery_guard.models import CompromisedAccountFinding
from account_recovery_guard.reset_orchestrator import (
    PasswordResetOrchestrator,
    ResetLinkSafetyError,
    is_blocked_recovery_download_url,
    open_reset_link_window,
    validate_browser_reset_link,
)


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


def test_browser_reset_link_validation_allows_expected_https_domain():
    link = validate_browser_reset_link("https://example.com/reset", "example.com")

    assert link == "https://example.com/reset"


def test_browser_validation_allows_official_site_fallback_url():
    link = validate_browser_reset_link("https://example.com", "https://example.com")

    assert link == "https://example.com"


def test_browser_reset_link_validation_rejects_http_link():
    with pytest.raises(ResetLinkSafetyError):
        validate_browser_reset_link("http://example.com/reset", "example.com")


def test_browser_reset_link_validation_rejects_embedded_credentials():
    with pytest.raises(ResetLinkSafetyError):
        validate_browser_reset_link("https://example.com@evil.test/reset", "example.com")


def test_browser_reset_link_validation_rejects_unsafe_redirect():
    with pytest.raises(ResetLinkSafetyError):
        validate_browser_reset_link(
            "https://example.com/reset?next=https%3A%2F%2Fevil.test%2Fsteal",
            "example.com",
        )


@pytest.mark.parametrize(
    "url",
    (
        "https://example.com/security-update.exe",
        "https://example.com/recovery/reset-kit.zip?token=abc",
        "https://example.com/account/password-reset.dmg",
        "https://example.com/scripts/recover-account.ps1",
    ),
)
def test_browser_reset_link_validation_rejects_direct_download_urls(url):
    with pytest.raises(ResetLinkSafetyError):
        validate_browser_reset_link(url, "example.com")


def test_recovery_browser_blocks_common_malware_download_urls():
    assert is_blocked_recovery_download_url("https://example.com/download/security-update.exe") is True
    assert is_blocked_recovery_download_url("https://example.com/files/recovery%20tool.pkg") is True
    assert is_blocked_recovery_download_url("https://example.com/archive/reset-kit.zip?token=abc") is True
    assert is_blocked_recovery_download_url("https://example.com/account/reset") is False


def test_open_reset_link_window_uses_non_prompt_browser_mode(monkeypatch):
    observed = {}

    async def fake_open(self, reset_link, expected_domain_or_url=None, wait_for_enter=True):
        observed["reset_link"] = reset_link
        observed["expected_domain_or_url"] = expected_domain_or_url
        observed["wait_for_enter"] = wait_for_enter

    monkeypatch.setattr(PasswordResetOrchestrator, "open_reset_link_for_manual_completion", fake_open)

    open_reset_link_window("https://example.com/reset", "example.com")

    assert observed == {
        "reset_link": "https://example.com/reset",
        "expected_domain_or_url": "example.com",
        "wait_for_enter": False,
    }
