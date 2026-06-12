from email.message import EmailMessage

from account_recovery_guard.account_discovery import AccountDiscovery


def _message(subject: str, sender: str, body: str = "body") -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["Date"] = "Fri, 12 Jun 2026 12:00:00 -0500"
    msg.set_content(body)
    return msg


def test_account_discovery_finds_likely_services_from_account_mail():
    messages = [
        _message("Welcome to Example", "hello@example.com"),
        _message("Verify your account", "accounts.service.test"),
        _message("Weekly marketing blast", "news@noise.test"),
    ]

    accounts = AccountDiscovery().discover(messages)

    assert [account.service_name for account in accounts] == ["example", "service"]
    assert accounts[0].confidence == "high"


def test_account_discovery_counts_repeated_service_signals():
    messages = [
        _message("New login to Example", "security@example.com"),
        _message("Password changed", "accounts@example.com"),
    ]

    accounts = AccountDiscovery().discover(messages)

    assert accounts[0].service_name == "example"
    assert accounts[0].message_count == 2
