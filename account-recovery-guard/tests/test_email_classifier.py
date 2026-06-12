from email.message import EmailMessage

from account_recovery_guard.email_scanner import EmailClassifier


def _message(subject: str, sender: str, body: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["Date"] = "Fri, 12 Jun 2026 12:00:00 -0500"
    msg.set_content(body)
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


def test_classifier_ignores_unrelated_newsletter():
    msg = _message(
        "June newsletter",
        "News <news@example.com>",
        "This month in product updates and community events.",
    )

    assert EmailClassifier().classify(msg) is None
