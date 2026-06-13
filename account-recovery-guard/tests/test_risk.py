from account_recovery_guard.models import CompromisedAccountFinding, DiscoveredAccount
from account_recovery_guard.risk import score_account_risk


def test_score_account_risk_combines_breach_and_mail_signals():
    account = DiscoveredAccount("example", "example.com", 3, "high", ["login/security email"])
    finding = CompromisedAccountFinding(
        service_name="example",
        sender_domain="example.com",
        sender="security@example.com",
        subject="Suspicious login",
        timestamp=None,
        severity="high",
        reasons=["suspicious activity"],
    )

    risk = score_account_risk("me@example.com", account, [finding], ["ExampleBreach"], password_reused=True)

    assert risk.compromised is True
    assert risk.score >= 80
    assert "known breach: ExampleBreach" in risk.reasons
    assert "password appears reused" in risk.reasons
