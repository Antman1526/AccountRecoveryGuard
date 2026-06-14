from email.message import EmailMessage

from account_recovery_guard.email_scanner import EmailClassifier, extract_body


def _message(subject: str, sender: str, body: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["Date"] = "Fri, 12 Jun 2026 12:00:00 -0500"
    msg.set_content(body)
    return msg


def _html_message(subject: str, sender: str, html: str, text: str = "") -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["Date"] = "Fri, 12 Jun 2026 12:00:00 -0500"
    msg.set_content(text or "Open the button to review your account.")
    msg.add_alternative(html, subtype="html")
    return msg


def test_classifier_extracts_high_severity_reset_alert():
    msg = _message(
        "Security alert: your account password was reset",
        "Security <security@example-service.com>",
        "We noticed a password reset. If this was not you, visit https://example-service.com/reset?token=abc",
    )

    finding = EmailClassifier().classify(msg)

    assert finding is not None
    assert finding.service_name == "example-service"
    assert finding.sender_domain == "example-service.com"
    assert finding.reset_link == "https://example-service.com/reset?token=abc"
    assert finding.severity == "high"


def test_classifier_extracts_reset_link_from_html_button_href():
    msg = _html_message(
        "Security alert: your account password was reset",
        "Security <security@example-service.com>",
        '<html><body><a href="https://example-service.com/reset?token=abc">Review account</a></body></html>',
    )

    finding = EmailClassifier().classify(msg)

    assert finding is not None
    assert finding.reset_link == "https://example-service.com/reset?token=abc"
    assert "https://example-service.com/reset?token=abc" in extract_body(msg)
    assert finding.severity == "high"


def test_html_extraction_ignores_non_web_href_schemes():
    msg = _html_message(
        "Security alert: your account password was reset",
        "Security <security@example-service.com>",
        '<html><body><a href="javascript:resetPassword()">Reset password</a></body></html>',
    )

    finding = EmailClassifier().classify(msg)

    assert finding is not None
    assert finding.reset_link is None
    assert "javascript:resetPassword" not in extract_body(msg)


def test_classifier_flags_mismatched_reset_link_as_phishing_risk():
    msg = _message(
        "Security alert: your account password was reset",
        "Dropbox Security <security@dropbox.com>",
        "If this was not you, visit https://dropbox.example.com/reset?token=abc",
    )

    finding = EmailClassifier().classify(msg)

    assert finding is not None
    assert finding.sender_domain == "dropbox.com"
    assert finding.reset_link == "https://dropbox.example.com/reset?token=abc"
    assert "reset/security link domain mismatch" in finding.reasons
    assert finding.severity == "critical"


def test_classifier_allows_same_service_reset_link_subdomain():
    msg = _message(
        "Security alert: your account password was reset",
        "Dropbox Security <security@security.dropbox.com>",
        "If this was not you, visit https://accounts.dropbox.com/reset?token=abc",
    )

    finding = EmailClassifier().classify(msg)

    assert finding is not None
    assert finding.sender_domain == "security.dropbox.com"
    assert finding.reset_link == "https://accounts.dropbox.com/reset?token=abc"
    assert "reset/security link domain mismatch" not in finding.reasons
    assert finding.severity == "high"


def test_classifier_ignores_unrelated_newsletter():
    msg = _message(
        "June newsletter",
        "News <news@example.com>",
        "This month in product updates and community events.",
    )

    assert EmailClassifier().classify(msg) is None
