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


def test_account_discovery_collects_multiple_reasons_without_double_counting_message():
    messages = [
        _message(
            "Your subscription renewal receipt",
            "billing@example.com",
            "Your account settings and passkey were updated after payment.",
        )
    ]

    accounts = AccountDiscovery().discover(messages)

    assert len(accounts) == 1
    account = accounts[0]
    assert account.service_name == "example"
    assert account.message_count == 1
    assert account.confidence == "high"
    assert "subscription/account email" in account.reasons
    assert "billing account email" in account.reasons
    assert "transactional account email" in account.reasons
    assert "MFA/passkey account email" in account.reasons
    assert "account settings email" in account.reasons


def test_account_discovery_finds_security_setting_and_mfa_account_mail():
    messages = [
        _message("Your security settings changed", "security@example.com", "Authenticator and two-factor settings changed."),
    ]

    accounts = AccountDiscovery().discover(messages)

    assert accounts[0].service_name == "example"
    assert accounts[0].message_count == 1
    assert "account settings email" in accounts[0].reasons
    assert "MFA/passkey account email" in accounts[0].reasons
