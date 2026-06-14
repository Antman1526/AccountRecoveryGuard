from account_recovery_guard.breach_checker import HibpBreach
from account_recovery_guard.exposure import SAFE_EXPOSURE_BOUNDARY, build_exposure_report
from account_recovery_guard.models import CompromisedAccountFinding, DiscoveredAccount


def test_exposure_report_prioritizes_breached_and_mail_flagged_services():
    accounts = [
        DiscoveredAccount("dropbox", "dropbox.com", 3, "high", ["account security email"]),
        DiscoveredAccount("newsletter", "newsletter.example", 1, "low", ["receipt"]),
    ]
    findings = [
        CompromisedAccountFinding(
            service_name="github",
            sender_domain="github.com",
            sender="security@github.com",
            subject="Suspicious login detected",
            timestamp=None,
            severity="high",
            reasons=["suspicious activity"],
        )
    ]

    report = build_exposure_report(
        "me@example.com",
        [HibpBreach("Dropbox")],
        accounts,
        findings,
        password_pwned_count=None,
    )

    assert report.breach_count == 1
    assert report.rotation_count == 2
    assert report.safety_boundary == SAFE_EXPOSURE_BOUNDARY
    by_service = {item.service_name: item for item in report.recommendations}
    assert by_service["dropbox"].rotate is True
    assert by_service["dropbox"].priority == "high"
    assert "known breach for this email: Dropbox" in by_service["dropbox"].reasons
    assert by_service["github"].rotate is True
    assert by_service["github"].priority == "high"
    assert by_service["newsletter"].rotate is False


def test_pwned_password_marks_discovered_accounts_for_rotation_without_plaintext():
    accounts = [DiscoveredAccount("bank", "bank.example", 2, "medium", ["login email"])]

    report = build_exposure_report(
        "me@example.com",
        [],
        accounts,
        [],
        password_pwned_count=42,
    )

    assert report.password_pwned_count == 42
    assert report.rotation_count == 1
    recommendation = report.recommendations[0]
    assert recommendation.service_name == "bank"
    assert recommendation.priority == "high"
    assert recommendation.rotate is True
    assert any("checked password appears" in reason for reason in recommendation.reasons)
    assert "hunter2" not in repr(report).casefold()


def test_exposure_boundary_blocks_unsafe_whole_web_claims():
    report = build_exposure_report("me@example.com", [], [], [], None)

    assert "does not crawl" in report.safety_boundary
    assert "dark-web" in report.safety_boundary
    assert "plaintext passwords" in report.safety_boundary
