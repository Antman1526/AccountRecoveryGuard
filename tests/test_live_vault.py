from account_recovery_guard.live_vault_test import build_live_test_candidate, summarize_preflight
from account_recovery_guard.models import VaultPreflight


def test_build_live_test_candidate_uses_safe_marker_and_no_user_service():
    candidate = build_live_test_candidate("tester@example.com")

    assert candidate.service_name.startswith("ARG-LIVE-TEST-")
    assert candidate.username == "tester@example.com"
    assert candidate.url == "https://example.invalid/account-recovery-guard"


def test_summarize_preflight_reports_blockers():
    summary = summarize_preflight(VaultPreflight(bitwarden_cli_found=False, bitwarden_session_present=False))

    assert summary.ready is False
    assert "Bitwarden CLI not found" in summary.blockers
    assert "BW_SESSION is not set" in summary.blockers
